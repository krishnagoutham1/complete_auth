const User = require("../models/User");
const {
  verification_email,
  welcome_email,
  login_otp_email,
} = require("../utils/sendEmail");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const generateOtp = require("../utils/generateOtp");

const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "name, email and password are required" });
    }

    const existingUser = await User.findOne({ where: { email } });

    if (existingUser)
      return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    const activationToken = jwt.sign(
      { id: newUser.id },
      process.env.JWT_ACTIVATION_SECRET,
      { expiresIn: "10m" }
    );

    const verifyURL = `${process.env.FRONTEND_URL}/verify/${activationToken}`;

    await verification_email({
      to: email,
      name: name,
      verification_link: verifyURL,
    });

    return res.status(201).json({
      message:
        "User registered! Please check your email to activate your account.",
      data: { name, email },
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const decodedToken = await jwt.verify(
      token,
      process.env.JWT_ACTIVATION_SECRET
    );

    console.log(decodedToken);

    const user = await User.findByPk(decodedToken.id);

    console.log(user);

    if (user.is_verified) {
      return res
        .status(400)
        .json({ message: "Account already verified pls login" });
    }

    user.is_verified = true;
    user.status = "active";

    await user.save();

    await welcome_email({
      to: user.email,
      name: user.name,
    });

    return res.json({
      message: "Account verification successful pls login to continue",
    });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(400).json({
        message: "Token has expired, please request a new verification email.",
      });
    } else if (err.name === "JsonWebTokenError") {
      return res.status(400).json({
        message: "Invalid token, please request a new verification email.",
      });
    } else {
      console.error(err);
      return res
        .status(500)
        .json({ message: "Internal Server Error", error: err });
    }
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "email and password are required" });
    }

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(400).json({ message: "No user Found!!!" });
    }

    const isPasswordValid = bcrypt.compare(user.password, password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }

    if (!user.is_verified) {
      return res
        .status(400)
        .json({ message: "Please Activate your account to login" });
    }

    //  need to handle deleted user later

    if (user.otp_login) {
      const login_otp = generateOtp();

      await login_otp_email({
        to: email,
        otp: login_otp,
      });

      return res
        .status(200)
        .json({ message: "Otp sent successfully", id: user.id });
    } else {
      const previous_login = user.last_login;

      user.last_login = new Date();
      await user.save();

      return res.status(200).json({
        message: "login successfull",
        data: {
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
          last_login: previous_login,
        },
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
};

module.exports = { register, login, verifyEmail };
