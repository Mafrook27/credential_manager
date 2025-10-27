const bcrypt = require("bcryptjs");
const User = require('../Models/CRED_User');
const { generateToken } = require('../util/generateToken');
const logger = require('../util/Logger');
const nodemailer = require("nodemailer");
const  dotenv = require("dotenv");
dotenv.config();




const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_ID,

    pass: process.env.MAIL_PASS ,
  }
});



const auth = {
  // Register user
  register: async (req, res, next) => {
    try {
      const { name, email, password } = req.body;

      if (!name || !email || !password) {
        const error = new Error('Missing required fields');
        error.statusCode = 400;
        throw error;
      }

      const exists = await User.findOne({ email });
      if (exists) {
        const error = new Error('Email already exists');
        error.statusCode = 409;
        throw error;
      }

      const hashed = await bcrypt.hash(password, 10);

      const user = await User.create({
        name,
        email,
        password: hashed,
  
      });

    //   const token = generateToken({ id: user._id });

      res.status(201).json({
        success: true,
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isVerified: user.isVerified,
          },
        //   token
        }
      });
      logger.info(`New user registered: ${user.email} with role: ${user.role}`);
    } catch (error) {
      next(error); 
    }
  },

 // Login user
login: async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      const error = new Error('Email and password required');
      error.statusCode = 400;
      throw error;
    }

    const user = await User.findOne({ email });
    if (!user) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    user.lastLogin = Date.now();
    await user.save();
    req.loginUserId = user._id.toString(); 
    
    const token = generateToken({ id: user._id });

   //ttpOnly cookie method 
   res.cookie('token', token, {
  httpOnly: true,
  secure: false,         
  sameSite: 'lax',       
  maxAge: 60 * 60 * 1000
});

 
    res.json({
      success: true,
      data: {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          lastLogin: user.lastLogin
        },
        // token  //  if you want to support old frontend
      }
    });
    logger.info(`Login successful: ${user.email}`);
  } catch (error) {
    next(error);
  }
},


  // Logout user
  logout: async (req, res, next) => {
    try {
      logger.info(`User logout: ${req.user?.email}`); 

       res.clearCookie('token', {
      httpOnly: true,
      secure: false,     
      sameSite: 'lax'       
    });

      res.json({ 
        success: true,
        message: 'Logout successful' 
      });
    } catch (error) {
      next(error);
    }
  },
  resetPasswordReq: async (req, res, next) => {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email }).lean();

      if (!user) {
        const error = new Error('User not found or email not in our records');
        error.statusCode = 400;
        throw error;
      }

      const token = Math.floor(100000 + Math.random() * 900000).toString();
      const expiry = Date.now() + 10 * 60 * 1000;

      await User.updateOne(
        { email },
        {
          $set: {
            resetToken: token,
            resetTokenExpiry: expiry
          }
        }
      );

      await transporter.sendMail({
        from: process.env.AUTH_ID,
        to: email,
        subject: "Password Reset Code",
        text: `Your password reset code is: ${token}. It will expire in 10 minutes.`
      });

      res.json({ message: "Password reset code sent to email" });
    } catch (error) {
      logger.error("Reset request error", { message: error.message, stack: error.stack });
      next(error);
    }
  },

  resetPasswordverify: async (req, res, next) => {
    try {
      const { email, token, newPassword } = req.body;
      const user = await User.findOne({ email }).lean();

      if (!user) {
        const error = new Error('Email not found in our records');
        error.statusCode = 400;
        throw error;
      }

      if (user.resetToken !== token || Date.now() > user.resetTokenExpiry) {
        const error = new Error('Invalid or expired token');
        error.statusCode = 400;
        throw error;
      }

      const hashed = await bcrypt.hash(newPassword, 10);

      await User.updateOne(
        { email },
        {
          $set: {
            password: hashed
          },
          $unset: {
            resetToken: "",
            resetTokenExpiry: ""
          }
        }
      );  

      res.json({ message: "Password reset successful" });
    } catch (error) {
      logger.error("Reset verify error", { message: error.message, stack: error.stack });
      next(error);
    }
  }


}

module.exports = auth;