import {
  BadRequestException,
  Body,
  Controller,
  Post,
  // UseGuards,
} from '@nestjs/common';

//SERVICE
import { AuthService } from './auth.service';

//DTO's
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';

//INTERFACE
import { AuthResponse } from '../interface/auth-response.interface';
// import { AuthGuard } from '@nestjs/passport';

@Controller('')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/register')
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponse> {
    try {
      return await this.authService.register(registerDto);
    } catch (error) {
      console.log(error);
      throw new BadRequestException('Bad Request, Register Failed');
    }
  }

  @Post('/login')
  // @UseGuards(AuthGuard('local'))
  async login(@Body() loginDto: LoginDto): Promise<AuthResponse> {
    return await this.authService.login(loginDto);
  }
}
