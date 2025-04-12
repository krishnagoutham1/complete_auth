require("dotenv").config();
const sgMail = require("@sendgrid/mail");

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendVerificationEmail = async ({ to, name, verification_link }) => {
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
    console.log(`✅ Verification email sent to ${to}`);
  } catch (err) {
    console.error(
      "❌ Error sending verification email:",
      err.response?.body || err.message
    );
    throw new Error(`Verification email not sent to ${to}: ${err.message}`);
  }
};

const sendWelcomeEmail = async ({ to, name }) => {
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
    console.log(`✅ Welcome email sent to ${to}`);
  } catch (err) {
    console.error(
      "❌ Error sending welcome email:",
      err.response?.body || err.message
    );
    throw new Error(`Welcome email not sent to ${to}: ${err.message}`);
  }
};

const sendLoginOtpEmail = async ({ to, otp }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      subject: "Your Login OTP",
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Your OTP for login</h2>
          <h1 style="color: #1a73e8;">${otp}</h1>
          <p>This OTP is valid for 10 minutes. Do not share it with anyone.</p>
        </div>
      `,
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

const sendResetPasswordEmail = async ({ to, link }) => {
  try {
    const msg = {
      to,
      from: { email: process.env.EMAIL_FROM, name: process.env.EMAIL_NAME },
      subject: "Reset Your Password",
      html: `
        <div style="font-family: Arial, sans-serif;">
          <h2>Password Reset Request</h2>
          <p>Click the button below to reset your password:</p>
          <a href="${link}" style="display:inline-block;padding:10px 15px;background-color:#1a73e8;color:#fff;text-decoration:none;border-radius:5px;">Reset Password</a>
          <p>If you did not request this, please ignore this email.</p>
        </div>
      `,
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
