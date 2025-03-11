const User = require("../models/User");
const { verification_email } = require("../utils/sendEmail");
const jwt = require("jsonwebtoken");

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // 1. Check if user already exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser)
      return res.status(400).json({ message: "Email already exists" });

    // 2. Create the user (unverified)
    const newUser = await User.create({
      name,
      email,
      password, // hash password if not done already!
      is_verified: false,
    });

    // 3. Generate activation token (JWT with expiry)
    const activationToken = jwt.sign(
      { id: newUser.id },
      process.env.JWT_ACTIVATION_SECRET,
      { expiresIn: "10m" } // token valid for 10 minutes
    );

    // 4. Save the token in DB (optional if token is stateless JWT)
    await newUser.update({ activation_token: activationToken });

    // 5. Build the verification URL
    const verifyURL = `${process.env.FRONTEND_URL}/verify/${activationToken}`;

    // 6. Prepare the email HTML content or dynamic templete

    // 7. Send the email
    await verification_email({
      to: email,
      name: name,
      verification_link: verifyURL,
    });

    res.status(201).json({
      message:
        "User registered! Please check your email to activate your account.",
      data: { name, email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
};

module.exports = { register };
