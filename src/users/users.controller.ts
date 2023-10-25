import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Get,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from './models/users.model';
import { SignupDto } from './dto/signup.dto';
import { SigninDto } from './dto/signin.dto';
import { AuthGuard } from '@nestjs/passport';
@Controller('users')
export class UsersController {
  constructor(private readonly userServices: UsersService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  public async signup(@Body() signupDTO: SignupDto): Promise<User> {
    return this.userServices.signup(signupDTO);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  public async signin(
    @Body() signinDTO: SigninDto,
  ): Promise<{ name: string; email: string; jwtToken: string }> {
    return this.userServices.signin(signinDTO);
  }

  @Get()
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  public findAll(): Promise<User[]> {
    return this.userServices.findAll();
  }
}
