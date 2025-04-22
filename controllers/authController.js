const bcrypt = require("bcryptjs");
const User = require("../models/User");
const generateToken = require("../utils/generateToken");
const sendEmail = require("../utils/sendEmail");
const crypto = require("crypto");

exports.register = async (req, res) => {
    const { email, password } = req.body;
  
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already registered" });
  
    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = crypto.randomBytes(32).toString("hex");
  
    const user = await User.create({
      email,
      password: hashed,
      verifyToken,
    });
  
    const verifyLink = `http://localhost:3000/verify-email/${verifyToken}`;
    await sendEmail(email, "Verifikasi Email", `<p>Klik untuk verifikasi: <a href="${verifyLink}">${verifyLink}</a></p>`);
  
    res.json({ message: "Registrasi berhasil. Silakan cek email untuk verifikasi." });
  };

exports.login = async (req, res) => {
    const { email, password } = req.body;
  
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
        return res.status(401).json({ message: "Email atau password salah" });
  
    if (!user.isVerified)
        return res.status(401).json({ message: "Silakan verifikasi email Anda terlebih dahulu" });
  
    res.json({ token: generateToken(user) });
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });

  const token = crypto.randomBytes(20).toString("hex");
  user.resetToken = token;
  user.resetTokenExpiration = Date.now() + 3600000;
  await user.save();

  const resetLink = `http://localhost:3000/reset-password/${token}`;
  await sendEmail(email, "Reset Password", `<a href="${resetLink}">${resetLink}</a>`);

  res.json({ message: "Reset email sent" });
};

exports.resetPassword = async (req, res) => {
  const { token, new_password } = req.body;

  const user = await User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: Date.now() },
  });

  if (!user) return res.status(400).json({ message: "Invalid or expired token" });

  user.password = await bcrypt.hash(new_password, 10);
  user.resetToken = undefined;
  user.resetTokenExpiration = undefined;
  await user.save();

  res.json({ message: "Password has been reset" });
};

exports.verifyEmail = async (req, res) => {
    const { token } = req.params;
  
    const user = await User.findOne({ verifyToken: token });
    if (!user) return res.status(400).json({ message: "Token tidak valid" });
  
    user.isVerified = true;
    user.verifyToken = undefined;
    await user.save();
  
    res.json({ message: "Email berhasil diverifikasi" });
  };