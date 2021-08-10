import {
  IUserPersistance,
  IFieldMap,
  IUser,
  ISession,
  FindAuthenticationStrategyResponse,
  ISessionPersistance,
} from "@kaviar/security-bundle";
import { Collection, ObjectID, Behaviors } from "@kaviar/mongo-bundle";
import jwtDecode from "jwt-decode";

export class SessionsCollection<T extends ISession>
  extends Collection<ISession>
  implements ISessionPersistance {
  static collectionName = "sessions";

  static indexes = [
    {
      key: {
        token: 1,
      },
    },
  ];

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
    let data :any =jwtDecode(token)
    return {
      userId: data.username,
      expiresAt: new Date(data.exp),
      token:token,
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
