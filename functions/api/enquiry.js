const MAX_FILE_BYTES = 5 * 1024 * 1024;

const ALLOWED_EXTENSIONS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png"
]);

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

function clean(value, max = 2000) {
  return String(value ?? "").trim().slice(0, max);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeFilename(name) {
  return String(name || "attachment")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .slice(0, 120);
}

/* -------------------------------------------------------
   CLOUDFLARE TURNSTILE VERIFICATION
------------------------------------------------------- */

async function verifyTurnstile(env, token, remoteIp) {
  if (!env.TURNSTILE_SECRET_KEY) {
    console.error("TURNSTILE_SECRET_KEY is not configured.");
    return false;
  }

  if (!token) {
    return false;
  }

  const body = new FormData();

  body.append("secret", env.TURNSTILE_SECRET_KEY);
  body.append("response", token);

  if (remoteIp) {
    body.append("remoteip", remoteIp);
  }

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        body
      }
    );

    if (!response.ok) {
      console.error(
        "Turnstile verification HTTP error:",
        response.status
      );
      return false;
    }

    const result = await response.json();

    if (!result.success) {
      console.warn(
        "Turnstile verification failed:",
        result["error-codes"] || []
      );
      return false;
    }

    return true;

  } catch (error) {
    console.error("Turnstile verification error:", error);
    return false;
  }
}

/* -------------------------------------------------------
   RESEND EMAIL
------------------------------------------------------- */

async function sendResendEmail(env, payload) {
  if (!env.RESEND_API_KEY || !env.ADMIN_EMAIL || !env.FROM_EMAIL) {
    return { ok: false, skipped: true };
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const text = await response.text();

    console.error(
      "Resend error:",
      response.status,
      text
    );

    return {
      ok: false,
      skipped: false
    };
  }

  return {
    ok: true,
    skipped: false
  };
}

/* -------------------------------------------------------
   ENQUIRY POST HANDLER
------------------------------------------------------- */

export async function onRequestPost(context) {
  const { request, env } = context;

  try {

    if (!env.DB) {
      return json(
        { error: "Enquiry storage is not configured yet." },
        503
      );
    }

    const contentType =
      request.headers.get("content-type") || "";

    if (!contentType.includes("multipart/form-data")) {
      return json(
        { error: "Invalid form submission." },
        415
      );
    }

    const form = await request.formData();

    /* ---------------------------------------------------
       HONEYPOT
    --------------------------------------------------- */

    if (clean(form.get("website"), 200)) {
      return json({
        ok: true,
        reference: "received",
        notificationSent: true
      });
    }

    /* ---------------------------------------------------
       TURNSTILE
    --------------------------------------------------- */

    const turnstileToken = clean(
      form.get("cf-turnstile-response"),
      4096
    );

    const remoteIp =
      request.headers.get("CF-Connecting-IP") || "";

    const turnstileValid =
      await verifyTurnstile(
        env,
        turnstileToken,
        remoteIp
      );

    if (!turnstileValid) {
      return json(
        {
          error:
            "Security verification failed. Please refresh the page and try again."
        },
        403
      );
    }

    /* ---------------------------------------------------
       FORM DATA
    --------------------------------------------------- */

    const data = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),

      name: clean(form.get("name"), 120),
      company: clean(form.get("company"), 160),

      email: clean(
        form.get("email"),
        200
      ).toLowerCase(),

      phone: clean(form.get("phone"), 80),
      country: clean(form.get("country"), 120),

      product: clean(form.get("product"), 160),
      quantity: clean(form.get("quantity"), 120),

      packaging: clean(form.get("packaging"), 300),

      specification: clean(
        form.get("specification"),
        5000
      ),

      destination: clean(
        form.get("destination"),
        300
      ),

      price: clean(form.get("price"), 200),

      timeline: clean(
        form.get("timeline"),
        200
      ),

      additional: clean(
        form.get("additional"),
        5000
      ),

      enquirySource: clean(
        form.get("enquiry_source"),
        1000
      )
    };

    /* ---------------------------------------------------
       REQUIRED FIELDS
    --------------------------------------------------- */

    const required = [
      ["name", data.name],
      ["company", data.company],
      ["email", data.email],
      ["country", data.country],
      ["product", data.product],
      ["quantity", data.quantity],
      ["destination", data.destination]
    ];

    for (const [field, value] of required) {

      if (!value) {
        return json(
          {
            error:
              `Missing required field: ${field}.`
          },
          400
        );
      }
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        data.email
      )
    ) {
      return json(
        {
          error:
            "Please enter a valid business email address."
        },
        400
      );
    }

    if (!form.get("genuine_enquiry")) {
      return json(
        {
          error:
            "Please confirm that this is a genuine business sourcing enquiry."
        },
        400
      );
    }

    /* ---------------------------------------------------
       ATTACHMENT
    --------------------------------------------------- */

    let attachmentKey = null;
    let attachmentName = null;
    let attachmentType = null;
    let attachmentSize = null;

    const attachment =
      form.get("attachment");

    if (
      attachment instanceof File &&
      attachment.size > 0
    ) {

      if (
        attachment.size >
        MAX_FILE_BYTES
      ) {
        return json(
          {
            error:
              "Attachment exceeds the 5 MB limit."
          },
          413
        );
      }

      const extension =
        (
          attachment.name
            .split(".")
            .pop() || ""
        ).toLowerCase();

      if (
        !ALLOWED_EXTENSIONS.has(
          extension
        )
      ) {
        return json(
          {
            error:
              "Unsupported attachment type."
          },
          400
        );
      }

      if (!env.RFQ_FILES) {
        return json(
          {
            error:
              "File storage is not configured yet."
          },
          503
        );
      }

      attachmentName =
        safeFilename(
          attachment.name
        );

      attachmentType =
        attachment.type ||
        "application/octet-stream";

      attachmentSize =
        attachment.size;

      attachmentKey =
        `enquiries/${data.id}/${attachmentName}`;

      await env.RFQ_FILES.put(
        attachmentKey,
        attachment.stream(),
        {
          httpMetadata: {
            contentType:
              attachmentType
          },

          customMetadata: {
            enquiryId: data.id,
            originalName:
              attachment.name
          }
        }
      );
    }

    /* ---------------------------------------------------
       STORE IN D1
    --------------------------------------------------- */

    try {

      await env.DB.prepare(`
        INSERT INTO enquiries (
          id,
          created_at,
          name,
          company,
          email,
          phone,
          country,
          product,
          quantity,
          packaging,
          specification,
          destination,
          price,
          timeline,
          additional,
          enquiry_source,
          attachment_key,
          attachment_name,
          attachment_type,
          attachment_size,
          status,
          admin_email_sent,
          acknowledgement_email_sent
        )
        VALUES (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?,
          'new', 0, 0
        )
      `).bind(

        data.id,
        data.createdAt,
        data.name,
        data.company,
        data.email,
        data.phone,
        data.country,
        data.product,
        data.quantity,
        data.packaging,
        data.specification,
        data.destination,
        data.price,
        data.timeline,
        data.additional,
        data.enquirySource,
        attachmentKey,
        attachmentName,
        attachmentType,
        attachmentSize

      ).run();

    } catch (dbError) {

      if (
        attachmentKey &&
        env.RFQ_FILES
      ) {
        await env.RFQ_FILES
          .delete(attachmentKey)
          .catch(() => {});
      }

      throw dbError;
    }

    /* ---------------------------------------------------
       REFERENCE NUMBER
    --------------------------------------------------- */

    const reference =
      `KGS-${data.createdAt
        .slice(0, 10)
        .replaceAll("-", "")}-${data.id
        .slice(0, 8)
        .toUpperCase()}`;

    /* ---------------------------------------------------
       ADMIN EMAIL
    --------------------------------------------------- */

    const rows = [

      ["Reference", reference],
      ["Name", data.name],
      ["Company", data.company],
      ["Email", data.email],

      [
        "Phone / WhatsApp",
        data.phone || "—"
      ],

      ["Country", data.country],
      ["Product", data.product],

      [
        "Required quantity",
        data.quantity
      ],

      [
        "Packaging",
        data.packaging || "—"
      ],

      [
        "Destination",
        data.destination
      ],

      [
        "Target price / Incoterm",
        data.price || "—"
      ],

      [
        "Target timeline",
        data.timeline || "—"
      ],

      [
        "Specification",
        data.specification || "—"
      ],

      [
        "Additional requirements",
        data.additional || "—"
      ],

      [
        "Attachment",
        attachmentName || "None"
      ]
    ];

    const tableHtml =
      rows
        .map(
          ([label, value]) =>

          `<tr>
            <td style="
              padding:8px 12px;
              border-bottom:1px solid #e9e5dc;
              font-weight:700;
              color:#081d3b;
              vertical-align:top
            ">
              ${escapeHtml(label)}
            </td>

            <td style="
              padding:8px 12px;
              border-bottom:1px solid #e9e5dc;
              color:#334155;
              white-space:pre-wrap
            ">
              ${escapeHtml(value)}
            </td>
          </tr>`

        )
        .join("");

    const adminResult =
      await sendResendEmail(
        env,
        {

          from:
            env.FROM_EMAIL,

          to: [
            env.ADMIN_EMAIL
          ],

          reply_to:
            data.email,

          subject:
            `New sourcing enquiry: ${data.product} — ${data.company}`,

          html: `
            <div style="
              font-family:Arial,sans-serif;
              max-width:760px;
              margin:auto
            ">

              <h2 style="
                color:#081d3b
              ">
                New Kedar Global Sourcing enquiry
              </h2>

              <p>
                A new buyer enquiry has been stored successfully.
              </p>

              <table style="
                border-collapse:collapse;
                width:100%;
                border:1px solid #e9e5dc
              ">
                ${tableHtml}
              </table>

              ${
                attachmentKey
                  ? `
                    <p>
                      <strong>
                        Attachment:
                      </strong>
                      stored in the private R2 bucket as
                      <code>
                        ${escapeHtml(
                          attachmentKey
                        )}
                      </code>.
                    </p>
                  `
                  : ""
              }

            </div>
          `
        }
      );

    /* ---------------------------------------------------
       BUYER ACKNOWLEDGEMENT
    --------------------------------------------------- */

    const ackResult =
      await sendResendEmail(
        env,
        {

          from:
            env.FROM_EMAIL,

          to: [
            data.email
          ],

          reply_to:
            env.ADMIN_EMAIL,

          subject:
            `We received your sourcing enquiry — ${reference}`,

          html: `
            <div style="
              font-family:Arial,sans-serif;
              max-width:680px;
              margin:auto;
              color:#334155
            ">

              <h2 style="
                color:#081d3b
              ">
                Thank you for contacting Kedar Global Sourcing
              </h2>

              <p>
                We have received your sourcing enquiry for
                <strong>
                  ${escapeHtml(
                    data.product
                  )}
                </strong>.
              </p>

              <p>
                Your reference is
                <strong>
                  ${escapeHtml(
                    reference
                  )}
                </strong>.
              </p>

              <p>
                We will review the product, specification,
                quantity, packaging and destination details
                before responding with the appropriate next step.
              </p>

              <p style="
                margin-top:28px
              ">
                Kedar Global Sourcing
                <br>

                <span style="
                  color:#c8922f
                ">
                  Connecting Markets. Delivering Value.
                </span>
              </p>

            </div>
          `
        }
      );

    /* ---------------------------------------------------
       EMAIL STATUS
    --------------------------------------------------- */

    await env.DB.prepare(`
      UPDATE enquiries
      SET
        admin_email_sent = ?,
        acknowledgement_email_sent = ?
      WHERE id = ?
    `)
      .bind(
        adminResult.ok ? 1 : 0,
        ackResult.ok ? 1 : 0,
        data.id
      )
      .run();

    /* ---------------------------------------------------
       SUCCESS
    --------------------------------------------------- */

    return json(
      {
        ok: true,
        reference,
        stored: true,
        notificationSent:
          adminResult.ok,
        acknowledgementSent:
          ackResult.ok
      },
      201
    );

  } catch (error) {

    console.error(
      "Enquiry submission failed:",
      error
    );

    return json(
      {
        error:
          "We could not process your enquiry right now. Please try again shortly."
      },
      500
    );
  }
}

/* -------------------------------------------------------
   GET NOT ALLOWED
------------------------------------------------------- */

export function onRequestGet() {
  return json(
    {
      error:
        "Method not allowed."
    },
    405
  );
}
