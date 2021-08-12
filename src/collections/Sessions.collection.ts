import {
  IUserPersistance,
  IFieldMap,
  IUser,
  ISession,
  FindAuthenticationStrategyResponse,
  ISessionPersistance,
} from "@kaviar/security-bundle";
import { Collection, ObjectID, Behaviors } from "@kaviar/mongo-bundle";
const request = require('request');
const jwkToPem = require('jwk-to-pem');
const jwt = require('jsonwebtoken');
import { Inject, Token } from "@kaviar/core";
import {
  USER_POOL_ID,
  POOL_REGION
} from "../constants";
const globalAny: any = global;
globalAny.fetch = require('node-fetch');



export class SessionsCollection<T extends ISession>
  extends Collection<ISession>
  implements ISessionPersistance {
  static collectionName = "sessions";
  userPoolId = this.container.get(USER_POOL_ID);

  pool_region = this.container.get(POOL_REGION);

  static indexes = [
    {
      key: {
        token: 1,
      },
    },
  ];

  validateJWT(token) {
    console.log('sdfdf', this.userPoolId, this.pool_region);

    return new Promise((resolve, reject) => {
      request({
        url: encodeURI(`https://cognito-idp.${this.pool_region}.amazonaws.com/${this.userPoolId}/.well-known/jwks.json`),
        json: true
      }, function (error, response, body) {
        if (!error && response.statusCode === 200) {
          let pems = {};
          var keys = body['keys'];
          for (var i = 0; i < keys.length; i++) {
            var key_id = keys[i].kid;
            var modulus = keys[i].n;
            var exponent = keys[i].e;
            var key_type = keys[i].kty;
            var jwk = { kty: key_type, n: modulus, e: exponent };
            var pem = jwkToPem(jwk);
            pems[key_id] = pem;
          }
          var decodedJwt = jwt.decode(token, { complete: true });
          if (!decodedJwt) {
            console.log("Not a valid JWT token");
            reject(new Error('Not a valid JWT token'));
          }
          var kid = decodedJwt.header.kid;
          var pem = pems[kid];
          if (!pem) {
            console.log('Invalid token');
            reject(new Error('Invalid token'));
          }
          jwt.verify(token, pem, function (err, payload) {
            if (err) {
              console.log("Invalid Token.");
              reject(new Error('Invalid token'));
            } else {
              console.log("Valid Token.");
              resolve("Valid token");
            }
          });
        } else {
          console.log("Error! Unable to download JWKs");
          reject(error);
        }
      });
    })

  }
  /**
   * Creates the session with the token and returns the token
   * @param userId
   * @param expiresAt
   * @param data
   */
  async newSession(userId: any, expiresAt: Date, data?: any): Promise<string> {
    const session = {
      token: generateToken(64),
      userId,
      expiresAt,
    };

    if (data) {
      Object.assign(session, { data });
    }

    await this.insertOne(session);

    return session.token;
  }

  async getSession(token: string): Promise<ISession> {
    let data: any = null;
    try {
      data = await this.validateJWT(token);
    } catch (e) {
      console.log(e);
      return null;
    }
    return {
      userId: token,
      expiresAt: new Date(data.exp),
      token: token,
      data
    }
  }

  async deleteSession(token: string): Promise<void> {
    await this.deleteOne({
      token,
    });
  }

  async deleteAllSessionsForUser(userId: any): Promise<void> {
    await this.deleteMany({
      userId,
    });
  }

  async cleanExpiredTokens(): Promise<void> {
    await this.deleteMany({
      expiresAt: {
        $lt: new Date(),
      },
    });
  }
}

const ALLOWED_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".split(
  ""
);

function generateToken(length) {
  var b = [];
  for (var i = 0; i < length; i++) {
    var j = (Math.random() * (ALLOWED_CHARS.length - 1)).toFixed(0);
    b[i] = ALLOWED_CHARS[j];
  }
  return b.join("");
}
