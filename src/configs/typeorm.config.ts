import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const getTypeOrmConfig = (): TypeOrmModuleOptions => {
  return {
    type: 'mongodb',
    url: process.env.MONGODB_URI,
    useNewUrlParser: true,
    useUnifiedTopology: true,
    entities: [__dirname + '/../**/*.entity.{js,ts}'],
    synchronize: true,
  };
};
