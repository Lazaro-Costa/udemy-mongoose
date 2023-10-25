import * as mongoose from 'mongoose';
import * as bcrypt from 'bcrypt';
export const UsersSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

UsersSchema.pre('save', async function (next) {
  try {
    if (!this.isModified('password')) return next();

    this['password'] = await bcrypt.hash(this['password'], 10);
    return next();
  } catch (error) {
    return next(error);
  }
});
