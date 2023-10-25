import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Request } from 'express';
import { sign } from 'jsonwebtoken';
import { Model } from 'mongoose';
import { JwtPayload } from 'src/users/models/jwt.payload.model';
import { User } from 'src/users/models/users.model';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('User')
    private readonly usersModel: Model<User>,
  ) {}
  public async createAccessToken(userId: string): Promise<string> {
    return sign({ userId }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRATION,
    });
  }

  public async validateUser(JwtPayload: JwtPayload): Promise<User> {
    const user = await this.usersModel.findOne({ _id: JwtPayload.userId });
    if (!user) throw new UnauthorizedException('User not found');
    return user;
  }
  private jwtExtractor(request: Request): string {
    const authHeader = request.headers.authorization;
    if (!authHeader) throw new BadRequestException('Bad request.');

    return authHeader.split(' ')[1]; //token
  }
  public returnJwtExtractor(): (resquest: Request) => string {
    return this.jwtExtractor;
  }
}
