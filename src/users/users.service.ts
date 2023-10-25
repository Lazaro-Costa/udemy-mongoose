import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { AuthService } from 'src/auth/auth.service';
import { User } from './models/users.model';
import { SignupDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';
import * as bcrypt from 'bcrypt';
@Injectable()
export class UsersService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
    private readonly authService: AuthService,
  ) {}

  public async signup(signupDTO: SignupDto): Promise<User> {
    const user = new this.usersModel(signupDTO);
    return user.save();
  }
  public async signin(
    signinDTO: SigninDto,
  ): Promise<{ name: string; email: string; jwtToken: string }> {
    const user = await this.findByEmail(signinDTO.email);
    const match = await this.checkPassword(signinDTO.password, user);

    if (!match) throw new NotFoundException('Invalid credentials');

    return {
      name: user.name,
      email: user.email,
      jwtToken: await this.authService.createAccessToken(user._id),
    };
  }

  public findAll(): Promise<User[]> {
    return this.usersModel.find();
  }

  private async findByEmail(email: string): Promise<User> {
    const user = await this.usersModel.findOne({ email });
    if (!user) throw new NotFoundException('Email not found');
    return user;
  }

  private async checkPassword(password: string, user: User): Promise<boolean> {
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw new NotFoundException('Password not found');
    return match;
  }
}
