require("dotenv").config();
const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const verification_email = async ({ to, name, verification_link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      templateId: process.env.SENDGRID_VERIFICATION_EMAIL_TEMPLATE_ID,
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

const welcome_email = async ({ to, name }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      templateId: process.env.SENDGRID_WELCOME_EMAIL_TEMPLATE_ID,
      dynamic_template_data: {
        name,
        subject: "Welcome to TechMindZ",
      },
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Error sending email:", err.response?.body || err.message);
    throw new Error("Email not sent");
  }
};

const login_otp_email = async ({ to, otp }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      subject: "Your login OTP",
      html: `<h1>${otp}</h1>`, // HTML content instead of plain text
    };

    await sgMail.send(msg);
    console.log(`✅ Email sent to ${to}`);
  } catch (err) {
    console.error("❌ Error sending email:", err.response?.body || err.message);
    throw new Error("Email not sent");
  }
};

const reset_password_link = async ({ to, link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      subject: "Reset Password Link",
      html: `<h1>your link : ${link}</h1>`,
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
  login_otp_email,
  reset_password_link,
};
