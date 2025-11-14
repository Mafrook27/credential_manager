const bcrypt = require("bcryptjs");
const User = require('../models/CRED_User');
// const { generateToken } = require('../util/generateToken');
const logger = require('../util/Logger');
// const nodemailer = require("nodemailer");
// const { Resend } = require('resend');
const dotenv = require("dotenv");
const emailjs = require("@emailjs/nodejs");
dotenv.config();

emailjs.init({
  publicKey: process.env.EMAILJS_PUBLIC_KEY,
  privateKey: process.env.EMAILJS_PRIVATE_KEY,
});

// Add this logging right after init:
console.log("✅ SERVICE_ID:", process.env.EMAILJS_SERVICE_ID);
console.log("✅ TEMPLATE_ID:", process.env.EMAILJS_TEMPLATE_ID);
console.log("✅ PUBLIC_KEY:", process.env.EMAILJS_PUBLIC_KEY?.substring(0, 10) + "...");
console.log("✅ PRIVATE_KEY:", process.env.EMAILJS_PRIVATE_KEY ? "SET" : "NOT SET");

// const transporter = nodemailer.createTransport({
//   service: "gmail",
//   auth: {
//     user: process.env.AUTH_ID,

//     pass: process.env.MAIL_PASS,
//   }
// });


// const resend = new Resend(process.env.RESEND_API_KEY);

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
        message: 'register successful',
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isVerified: user.isVerified,
            isActive: user.isActive,


          },
          //   token
        }
      });
      logger.info(`New user registered: ${user.email} with role: ${user.role}`);
    } catch (error) {
      next(error);
    }
  },

  // Login user with session-based auth
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

      // Check if user is blocked
      if (!user.isActive) {
        const error = new Error('Your account has been blocked. Please contact administrator.');
        error.statusCode = 403;
        throw error;
      }

      user.lastLogin = Date.now();
      await user.save();
      req.loginUserId = user._id.toString();

      // Create session with access and refresh tokens
      const { createSession } = require('../util/generateToken');
      const Session = require('../models/Session');
      const userAgent = req.headers['user-agent'];
      const ipAddress = req.ip || req.connection.remoteAddress;

      // Check for existing sessions before creating new one
      const existingSessions = await Session.countDocuments({ userId: user._id, active: true });
      if (existingSessions > 0) {
        logger.info(`🔄 User ${user.email} has ${existingSessions} existing active session(s). Will invalidate them (Single session enforcement)...`);
      }

      const { accessToken, refreshToken } = await createSession(
        { id: user._id },
        userAgent,
        ipAddress
      );

      logger.info(`✅ New session created for user ${user.email}. Previous sessions invalidated.`);

      // Get token expiry times from env
      const getAccessMaxAge = () => {
        const time = process.env.ACCESS_TIME || "5m";
        if (time.endsWith('m')) return parseInt(time) * 60 * 1000;
        if (time.endsWith('h')) return parseInt(time) * 60 * 60 * 1000;
        if (time.endsWith('d')) return parseInt(time) * 24 * 60 * 60 * 1000;
        return 5 * 60 * 1000;
      };

      const getRefreshMaxAge = () => {
        const time = process.env.REFRESH_MAXTIME || "4h";
        if (time.endsWith('d')) return parseInt(time) * 24 * 60 * 60 * 1000;
        if (time.endsWith('h')) return parseInt(time) * 60 * 60 * 1000;
        if (time.endsWith('m')) return parseInt(time) * 60 * 1000;
        return 4 * 60 * 60 * 1000;
      };

      // Set cookies
      const isProd = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? 'none' : 'lax',
        path: '/'
      };

      // Access token cookie should live as long as refresh token
      // so frontend can send expired JWT and trigger refresh
      res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: getRefreshMaxAge()  // ✅ Use refresh token maxAge
      });

      res.cookie('refreshToken', refreshToken, {
        ...cookieOptions,
        maxAge: getRefreshMaxAge()
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            role: user.role,
            isVerified: user.isVerified,
            isActive: user.isActive,
            lastLogin: user.lastLogin
          }
        }
      });
      logger.info(`Login successful: ${user.email}`);
    } catch (error) {
      next(error);
    }
  },



  refreshToken: async (req, res, next) => {
    try {
      const refreshToken = req.cookies?.refreshToken;

      logger.info('🔄 Refresh token request received');

      if (!refreshToken) {
        logger.warn('❌ No refresh token in cookies');
        const error = new Error('No refresh token provided');
        error.statusCode = 401;
        error.code = 'NO_TOKEN';
        throw error;
      }

      const Session = require('../models/Session');
      const { verifyRefreshToken } = require('../util/jwtUtil');
      const { generateAccessToken } = require('../util/jwtUtil');

      // Find session and check if it's ACTIVE
      logger.info('🔍 Looking for session in database...');
      const session = await Session.findOne({ refreshToken });

      if (!session) {
        logger.warn('❌ Session not found - token may be invalid');
        const error = new Error('Session expired. Please login again.');
        error.statusCode = 401;
        error.code = 'SESSION_EXPIRED';
        throw error;
      }

      // Check if session is inactive (logged out or logged in elsewhere)
      if (!session.active) {
        logger.warn('❌ Session is inactive - user logged out or logged in from another device');
        const error = new Error('Session ended. You logged in from another device.');
        error.statusCode = 401;
        error.code = 'SESSION_INACTIVE';
        throw error;
      }

      // Check if session is expired
      if (session.expiresAt < new Date()) {
        logger.warn('❌ Session expired naturally');
        await Session.deleteOne({ _id: session._id });
        const error = new Error('Session expired. Please login again.');
        error.statusCode = 401;
        error.code = 'SESSION_EXPIRED';
        throw error;
      }

      logger.info(`✅ Active session found - User: ${session.userId}, Current refresh count: ${session.refreshCount}`);

      // Verify refresh token
      try {
        verifyRefreshToken(refreshToken);
        logger.info('✅ Refresh token verified successfully');
      } catch (err) {
        logger.error('❌ Refresh token verification failed:', err.message);
        await Session.deleteOne({ _id: session._id });
        const error = new Error('Session invalid. Please login again.');
        error.statusCode = 401;
        error.code = 'SESSION_EXPIRED';
        throw error;
      }

      // Check refresh limit (max 3 refreshes per session)
      const MAX_REFRESH_COUNT = parseInt(process.env.MAX_REFRESH_COUNT || '3');
      logger.info(`📊 Checking refresh limit: ${session.refreshCount}/${MAX_REFRESH_COUNT}`);

      if (session.refreshCount >= MAX_REFRESH_COUNT) {
        logger.warn(`❌ Refresh limit reached (${session.refreshCount}/${MAX_REFRESH_COUNT})`);
        await Session.deleteOne({ _id: session._id });
        const error = new Error('Session token expired . Please login again.');
        error.statusCode = 401;
        error.code = 'SESSION_EXPIRED';
        throw error;
      }

      // Increment refresh count
      session.refreshCount += 1;
      await session.save();
      logger.info(`✅ Refresh count incremented: ${session.refreshCount}/${MAX_REFRESH_COUNT}`);

      // Generate new access token
      const newAccessToken = generateAccessToken({ id: session.userId });

      // Get refresh token max age (access token cookie should match)
      const getRefreshMaxAge = () => {
        const time = process.env.REFRESH_MAXTIME || "4h";
        if (time.endsWith('d')) return parseInt(time) * 24 * 60 * 60 * 1000;
        if (time.endsWith('h')) return parseInt(time) * 60 * 60 * 1000;
        if (time.endsWith('m')) return parseInt(time) * 60 * 1000;
        return 4 * 60 * 60 * 1000;
      };

      const isProd = process.env.NODE_ENV === 'production';
      // Access token cookie should live as long as refresh token
      res.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? 'none' : 'lax',
        path: '/',
        maxAge: getRefreshMaxAge()  // ✅ Use refresh token maxAge
      });

      res.json({
        success: true,
        message: 'Access token refreshed',
        data: {
          refreshCount: session.refreshCount,
          maxRefreshCount: MAX_REFRESH_COUNT
        }
      });

      logger.info(`Token refreshed for user: ${session.userId}`);
    } catch (error) {
      next(error);
    }
  },

  // Logout user
  logout: async (req, res, next) => {
    try {
      const refreshToken = req.cookies?.refreshToken;

      // Mark session as inactive (keep for audit trail)
      if (refreshToken) {
        const Session = require('../models/Session');
        const result = await Session.updateOne(
          { refreshToken },
          { active: false }
        );

        if (result.modifiedCount > 0) {
          logger.info(`✅ Session marked inactive for logout`);
        }
      }

      const isProd = process.env.NODE_ENV === 'production';
      const cookieOptions = {
        httpOnly: true,
        secure: isProd,
        sameSite: isProd ? 'none' : 'lax',
        path: '/'
      };

      // Clear both tokens
      res.clearCookie('accessToken', cookieOptions);
      res.clearCookie('refreshToken', cookieOptions);

      res.json({
        success: true,
        message: 'Logout successful'
      });

      logger.info(`User logout successful`);
    } catch (error) {
      next(error);
    }
  },




  // resetPasswordReq: async (req, res, next) => {
  //   try {
  //     const { email } = req.body;
  //     const user = await User.findOne({ email }).lean();

  //     if (!user) {
  //       const error = new Error('User not found or email not in our records');
  //       error.statusCode = 400;
  //       throw error;
  //     }

  //     const token = Math.floor(100000 + Math.random() * 900000).toString();
  //     const expiry = Date.now() + 10 * 60 * 1000;

  //     await User.updateOne(
  //       { email },
  //       {
  //         $set: {
  //           resetToken: token,
  //           resetTokenExpiry: expiry
  //         }
  //       }
  //     );



  //     //   await transporter.sendMail({
  //     //     from: process.env.AUTH_ID,
  //     //     to: email,
  //     //     subject: "Password Reset Code",
  //     //     text: `Your password reset code is: ${token}. It will expire in 10 minutes.`
  //     //   });

  //     //   res.json({ message: "Password reset code sent to email" });


  //     // } catch (error) {
  //     //   logger.error("Reset request error", { message: error.message, stack: error.stack });
  //     //   next(error);
  //     // }






  //     // Try Resend first, fallback to Gmail if fails
  //     try {
  //       logger.info(`📧 Attempting to send reset email to ${email} via Resend...`);
  //       const { data, error } = await resend.emails.send({
  //         from: "onboarding@resend.dev",
  //         to: email,
  //         subject: "Password Reset Code",
  //         html: `
  //           <p>Your password reset code is <strong>${token}</strong>.</p>
  //           <p>This code will expire in <b>10 minutes</b>.</p>
  //         `,
  //       });

  //       if (error) {
  //         logger.error(`❌ Resend error details:`, error);
  //         throw error;
  //       }

  //       logger.info(`✅ Reset email sent to ${email} via Resend`, { data });
  //     } catch (resendErr) {
  //       logger.warn(`⚠️ Resend failed: ${resendErr.message}. Falling back to Gmail.`, {
  //         error: resendErr,
  //         resendApiKey: process.env.RESEND_API_KEY ? 'SET' : 'NOT SET'
  //       });

  //       try {
  //         logger.info(`📧 Attempting Gmail fallback for ${email}...`);
  //         await transporter.sendMail({
  //           from: process.env.AUTH_ID,
  //           to: email,
  //           subject: "Password Reset Code",
  //           text: `Your password reset code is: ${token}. It will expire in 10 minutes.`,
  //         });

  //         logger.info(`📩 Reset email sent to ${email} via Gmail fallback`);
  //       } catch (gmailErr) {
  //         logger.error(`❌ Gmail fallback also failed:`, {
  //           message: gmailErr.message,
  //           code: gmailErr.code,
  //           authId: process.env.AUTH_ID ? 'SET' : 'NOT SET',
  //           mailPass: process.env.MAIL_PASS ? 'SET' : 'NOT SET'
  //         });
  //         throw new Error('Failed to send email. Please try again later.');
  //       }
  //     }

  //     // In development, also return token for testing
  //     const response = { message: "Password reset code sent to email" };
  //     if (process.env.NODE_ENV === 'development') {
  //       response.token = token; // Only for testing
  //       logger.warn(`⚠️ DEV MODE: Reset token exposed in response: ${token}`);
  //     }

  //     res.json(response);
  //   } catch (error) {
  //     logger.error("Reset request error", { message: error.message, stack: error.stack });
  //     next(error);
  //   }
  // },



  resetPasswordReq: async (req, res, next) => {
    try {
      const { email } = req.body;

      if (!email) {
        const error = new Error('Email is required');
        error.statusCode = 400;
        throw error;
      }

      // Check if user exists
      const user = await User.findOne({ email }).lean();
      if (!user) {
        const error = new Error('User not found or email not in our records');
        error.statusCode = 400;
        throw error;
      }

      // Generate 6-digit reset token
      const token = Math.floor(100000 + Math.random() * 900000).toString();
      const expiry = Date.now() + 10 * 60 * 1000; // 10 minutes

      // Save token to database
      await User.updateOne(
        { email },
        {
          $set: {
            resetToken: token,
            resetTokenExpiry: expiry
          }
        }
      );

      logger.info(`🔑 Reset token generated for ${email}`);


      try {
        logger.info(`📧 Sending reset email to ${email}...`);

        const response = await emailjs.send(
          process.env.EMAILJS_SERVICE_ID,      // service_back_17
          process.env.EMAILJS_TEMPLATE_ID,     // template_z65i5joo
          {
            email: email,                       // Goes to {{email}} in template
            reset_token: token                  // Goes to {{reset_token}} in template
          },
          // {
          //   publicKey: process.env.EMAILJS_PUBLIC_KEY,
          //   privateKey: process.env.EMAILJS_PRIVATE_KEY,
          // }
        );

        logger.info(`✅ Reset email sent successfully to ${email}`, {
          messageId: response.text
        });

        res.json({
          success: true,
          message: "Password reset code has been sent to your email"
        });

      } catch (emailError) {
        logger.error("❌ EmailJS error:", {
          message: emailError.message,
          status: emailError.status,
          text: emailError.text
        });

        const error = new Error('Failed to send reset email. Please try again.');
        error.statusCode = 500;
        throw error;
      }

    } catch (error) {
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

      // ✅ CRITICAL: Invalidate all sessions when password is reset
      const Session = require('../models/Session');
      await Session.updateMany(
        { userId: user._id },
        { active: false }
      );

      logger.info(`🔒 Password reset successful for ${email}. All sessions invalidated.`);

      res.json({
        success: true,
        message: "Password reset successful. Please login with your new password."
      });
    } catch (error) {
      logger.error("Reset verify error", { message: error.message, stack: error.stack });
      next(error);
    }
  }


}

module.exports = auth;