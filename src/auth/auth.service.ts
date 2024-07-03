import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  // UnauthorizedException,
} from '@nestjs/common';
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
    try {
      const { name, username, password } = registerDto;
      if (!name) throw new BadRequestException('Name is required');
      if (!username) throw new BadRequestException('Username is required');
      if (!password) throw new BadRequestException('Password is required');

      const checkSameUsername = await this.userModel.findOne({
        username: username,
      });
      if (checkSameUsername)
        throw new BadRequestException(
          'This username has been registered, try another',
        );

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
    } catch (error) {
      throw new InternalServerErrorException('Error, check your request');
    }
  }

  async login(loginDto: LoginDto): Promise<AuthResponse> {
    try {
      const { username, password } = loginDto;
      if (!username) {
        throw new BadRequestException('Enter your Username');
      }

      const user = await this.userModel.findOne({ username });
      if (!user) {
        throw new BadRequestException(
          'Username is not found, Make sure the username has been registered',
        );
      }

      const isPasswordMatched = await bcrypt.compare(password, user.password);
      if (!isPasswordMatched) {
        throw new BadRequestException('Password is not match');
      }

      const token = this.jwtService.sign({ id: user._id });

      return {
        success: true,
        message: 'User has been logged in',
        token: token,
      };
    } catch (error) {
      console.log(error);
    }
  }

  async getAccount(): Promise<any> {
    try {
      const data = await this.userModel.find();
      if (!data) throw new NotFoundException('Data Not Found');

      return {
        success: true,
        message: 'Get All User Account Success',
        results: data,
      };
    } catch (error) {
      throw new NotFoundException('Users Not Found');
    }
  }
}
