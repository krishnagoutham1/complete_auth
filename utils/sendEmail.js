require("dotenv").config();
const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const welcome_email = async ({ to, subject, html }) => {
  try {
    const msg = {
      to,
      from: process.env.EMAIL_FROM,
      subject,
      html, // HTML content instead of plain text
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Error sending email:", err.response?.body || err.message);
    throw new Error("Email not sent");
  }
};

const verification_email = async ({ to, name, verification_link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: "TechMindZ" },
      templateId: process.env.SENDGRID_VERIFICATION_EMAI_TEMPLATE_ID,
      dynamic_template_data: {
        name,
        verification_link,
        subject: "Activate your TechMindZ Account",
      },
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Error sending email:", err.response?.body || err.message);
    throw new Error("Email not sent");
  }
};

const reset_password_email = async ({ to, subject, html }) => {
  try {
    const msg = {
      to,
      from: process.env.EMAIL_FROM,
      subject,
      html, // HTML content instead of plain text
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Error sending email:", err.response?.body || err.message);
    throw new Error("Email not sent");
  }
};

const login_otp_email = async ({ to, subject, html }) => {
  try {
    const msg = {
      to,
      from: process.env.EMAIL_FROM,
      subject,
      html, // HTML content instead of plain text
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Error sending email:", err.response?.body || err.message);
    throw new Error("Email not sent");
  }
};

module.exports = {
  welcome_email,
  verification_email,
  reset_password_email,
  login_otp_email,
};
