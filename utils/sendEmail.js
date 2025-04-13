require("dotenv").config();
const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const currentYear = new Date().getFullYear();

const sendVerificationEmail = async ({ to, name, verification_link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      templateId: process.env.SENDGRID_TEMPLATE_VERIFICATION_EMAIL,
      dynamic_template_data: {
        name,
        verification_link,
        subject: "Activate your TechMindZ Account",
        year: currentYear,
      },
    };

    await sgMail.send(msg);
    console.log(`✅ Verification email sent to ${to}`);
  } catch (err) {
    console.error(
      "❌ Error sending verification email:",
      err.response?.body || err.message
    );
    throw new Error(`Verification email not sent to ${to}: ${err.message}`);
  }
};

const sendWelcomeEmail = async ({ to, name, dashboard_link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      templateId: process.env.SENDGRID_TEMPLATE_WELCOME_EMAIL,
      dynamic_template_data: {
        name,
        subject: "Welcome to TechMindZ",
        year: currentYear,
        dashboard_link,
      },
    };

    await sgMail.send(msg);
    console.log(`✅ Welcome email sent to ${to}`);
  } catch (err) {
    console.error(
      "❌ Error sending welcome email:",
      err.response?.body || err.message
    );
    throw new Error(`Welcome email not sent to ${to}: ${err.message}`);
  }
};

const sendLoginOtpEmail = async ({ to, name, otp }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      templateId: process.env.SENDGRID_TEMPLATE_LOGIN_OTP,
      dynamic_template_data: {
        name,
        otp,
        subject: "Your TechMindZ Login OTP",
        year: currentYear,
      },
    };

    await sgMail.send(msg);
    console.log(`✅ OTP email sent to ${to}`);
  } catch (err) {
    console.error(
      "❌ Error sending OTP email:",
      err.response?.body || err.message
    );
    throw new Error(`OTP email not sent to ${to}: ${err.message}`);
  }
};

const sendResetPasswordEmail = async ({ to, name, reset_link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      templateId: process.env.SENDGRID_TEMPLATE_RESET_PASSWORD_LINK,
      dynamic_template_data: {
        name,
        reset_link,
        subject: "Reset Your TechMindZ Password",
        year: currentYear,
      },
    };

    await sgMail.send(msg);
    console.log(`✅ Password reset email sent to ${to}`);
  } catch (err) {
    console.error(
      "❌ Error sending password reset email:",
      err.response?.body || err.message
    );
    throw new Error(`Password reset email not sent to ${to}: ${err.message}`);
  }
};

module.exports = {
  sendWelcomeEmail,
  sendVerificationEmail,
  sendLoginOtpEmail,
  sendResetPasswordEmail,
};
