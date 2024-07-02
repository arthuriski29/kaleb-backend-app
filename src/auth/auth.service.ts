import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

//SCHEMAS
import { User } from '../schemas/user.schema';

//DTO'S
import { RegisterDto } from '../dto/register.dto';
import { LoginDto } from '../dto/login.dto';

import { AuthResponse } from '../interface/auth-response.interface';

import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponse> {
    const { name, username, password } = registerDto;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.userModel.create({
      name,
      username,
      password: hashedPassword,
    });

    const token = this.jwtService.sign({ id: user._id });

    return {
      success: true,
      message: 'User has been created successfully',
      token: token,
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponse> {
    try {
      const { username, password } = loginDto;
      if (!username) {
        throw new UnauthorizedException('Enter your Username');
      }

      const user = await this.userModel.findOne({ username });

      const isPasswordMatched = await bcrypt.compare(password, user.password);
      if (!isPasswordMatched) {
        throw new UnauthorizedException('Password is not match');
      }

      const token = this.jwtService.sign({ id: user._id });

      return {
        success: true,
        message: 'User has been logged in',
        token: token,
      };
    } catch (error) {
      throw new UnauthorizedException('Unauthorized check your request');
    }
  }
}
