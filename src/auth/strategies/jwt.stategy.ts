import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { AuthService } from '../auth.service';
import { Strategy } from 'passport-jwt';
import { JwtPayload } from 'src/users/models/jwt.payload.model';
import { User } from 'src/users/models/users.model';

@Injectable()
export class jwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly authService: AuthService) {
    super({
      jwtFromRequest: authService.returnJwtExtractor(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }
  public async validate(jwtPayload: JwtPayload): Promise<User> {
    const user = await this.authService.validateUser(jwtPayload);
    if (!user) throw new UnauthorizedException('User not found');
    return user;
  }
}
