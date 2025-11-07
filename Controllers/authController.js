const bcrypt = require("bcryptjs");
const User = require('../models/CRED_User');
const logger = require('../util/Logger');
const { Resend } = require('resend');
const dotenv = require("dotenv");
dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);

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
      const existingSessions = await Session.countDocuments({ userId: user._id });
      if (existingSessions > 0) {
        logger.info(`🔄 User ${user.email} has ${existingSessions} existing session(s). Deleting old sessions...`);
      }

      const { accessToken, refreshToken } = await createSession(
        { id: user._id },
        userAgent,
        ipAddress
      );

      logger.info(`✅ New session created for user ${user.email}. Old sessions deleted.`);

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

      // Find session
      logger.info('🔍 Looking for session in database...');
      const session = await Session.findOne({ refreshToken });

      if (!session) {
        logger.warn('❌ Session not found in database (may have been deleted by new login)');
        const error = new Error('Session invalid or logged in from another device. Please login again.');
        error.statusCode = 401;
        error.code = 'SESSION_EXPIRED';
        throw error;
      }

      logger.info(`✅ Session found - User: ${session.userId}, Current refresh count: ${session.refreshCount}`);

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

      // Delete session from database
      if (refreshToken) {
        const Session = require('../models/Session');
        await Session.deleteOne({ refreshToken });
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



      //   await transporter.sendMail({
      //     from: process.env.AUTH_ID,
      //     to: email,
      //     subject: "Password Reset Code",
      //     text: `Your password reset code is: ${token}. It will expire in 10 minutes.`
      //   });

      //   res.json({ message: "Password reset code sent to email" });


      // } catch (error) {
      //   logger.error("Reset request error", { message: error.message, stack: error.stack });
      //   next(error);
      // }






      // Resend sandbox mode: only works for verified email
      try {
        logger.info(`📧 Sending reset email to ${email}...`);

        const { data, error } = await resend.emails.send({
          from: "onboarding@resend.dev",
          to: [email], // Must be array
          subject: "Password Reset Code - SparkLMS",
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #2962FF;">Password Reset Request</h2>
              <p>Your password reset code is:</p>
              <div style="background: #f5f5f5; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; border-radius: 8px;">
                ${token}
              </div>
              <p>This code will expire in <strong>10 minutes</strong>.</p>
              <p style="color: #666; font-size: 14px; margin-top: 30px;">If you didn't request this, please ignore this email.</p>
            </div>
          `,
        });

        if (error) {
          logger.error(`❌ Resend error:`, error);
          // Provide helpful error message
          if (error.message.includes('not verified') || error.message.includes('domain')) {
            throw new Error('Email service configuration error. Please add your email to Resend audience at https://resend.com/audiences');
          }
          throw new Error(error.message);
        }

        logger.info(`✅ Reset email sent successfully`);
      } catch (emailErr) {
        logger.error(`❌ Email failed:`, emailErr.message);
        throw new Error(emailErr.message || 'Failed to send email. Please try again later.');
      }

      // In development, also return token for testing
      const response = { message: "Password reset code sent to email" };
      if (process.env.NODE_ENV === 'development') {
        response.token = token; // Only for testing
        logger.warn(`⚠️ DEV MODE: Reset token exposed in response: ${token}`);
      }

      res.json(response);
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