declare namespace NodeJs {
  export interface ProcessEnv {
    DATABASE_URL: string;
    jwtSecretkey: string;
    jwtrefreshTokenKey: string;
  }
}
