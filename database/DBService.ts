import { Sequelize } from "sequelize";
import dotenv from 'dotenv';

dotenv.config();

export default class DBServices {
    public sequelizeWriter: Sequelize;
    public sequelizeReader: Sequelize;

    constructor() {
        this.sequelizeWriter = this.createSequelizeWriter();
        this.sequelizeReader = this.createSequelizeReader();
    }

    private createSequelizeWriter(): Sequelize {
        return new Sequelize({
            database: process.env.PGDATABASE_WRITER,
            username: process.env.PGUSER_WRITER,
            password: process.env.PGPASSWORD_WRITER,
            host: process.env.PGHOST_WRITER,
            port: parseInt(process.env.PGPORT_WRITER || '5432'),
            dialect: "postgres",
            dialectOptions: process.env.PG_USE_SSL === 'true' ? {
                ssl: {
                    require: true,
                    rejectUnauthorized: false
                }
            } : {},
            pool: {
                max: parseInt(process.env.PGMAXCONNECTIONS_WRITER || '200'),
                min: parseInt(process.env.PGMINCONNECTIONS_WRITER || '4'),
                idle: parseInt(process.env.PGIDLETIMEOUTMILLIS_WRITER || '1000'),
                acquire: parseInt(process.env.PGCONNECTIONTIMEOUTMILLIS_WRITER || '3000')
            },
            define: {
                underscored: true,
                timestamps: true,
            },
            logging: process.env.NODE_ENV === 'development' ? console.log : false
        });
    }

    private createSequelizeReader(): Sequelize {
        return new Sequelize({
            database: process.env.PGDATABASE_READER,
            username: process.env.PGUSER_READER,
            password: process.env.PGPASSWORD_READER,
            host: process.env.PGHOST_READER,
            port: parseInt(process.env.PGPORT_READER || '5432'),
            dialect: "postgres",
            dialectOptions: process.env.PG_USE_SSL === 'true' ? {
                ssl: {
                    require: true,
                    rejectUnauthorized: false
                }
            } : {},
            pool: {
                max: parseInt(process.env.PGMAXCONNECTIONS_READER || '200'),
                min: parseInt(process.env.PGMINCONNECTIONS_READER || '4'),
                idle: parseInt(process.env.PGIDLETIMEOUTMILLIS_READER || '1000'),
                acquire: parseInt(process.env.PGCONNECTIONTIMEOUTMILLIS_READER || '3000')
            },
            define: {
                underscored: true,
                timestamps: true,
            },
            logging: process.env.NODE_ENV === 'development' ? console.log : false
        });
    }

    public async testConnections(): Promise<void> {
        try {
            await this.sequelizeWriter.authenticate();
            console.log('✅ Writer connection established');
            await this.sequelizeReader.authenticate();
            console.log('✅ Reader connection established');
        } catch (error) {
            console.error('❌ Database connection failed:', error);
            throw error;
        }
    }
}
