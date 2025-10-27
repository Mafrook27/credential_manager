const bcrypt = require("bcryptjs");
const User = require("../Models/CRED_User");
const logger= require("../util/Logger");

async function seedAdmin() {
  try {
    const adminEmail ="admin@example.com";
    const adminPassword = "Admin@123";

    const existingAdmin = await User.findOne({ email: adminEmail, role: "admin" });
    if (existingAdmin) {
      logger.warn(`\n Admin already exists: ${existingAdmin.email} \n password: ${adminPassword} \n`);
      return;
    }

    const hashed = await bcrypt.hash(adminPassword, 10);

    const admin = new User({
      name: "Admin",
      email: adminEmail,
      password: hashed,
      role: "admin",
      isVerified: true,
    });

    await admin.save();
    logger.verbose(` Admin created successfully → ${admin.email}`);
  } catch (err) {
    logger.error("Admin seeding failed:", err.message, { stack: err.stack } );
  }
}

module.exports = seedAdmin;
