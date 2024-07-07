import { db } from "../connect.js";
import crypto from "crypto";
import { modPow } from "bigint-crypto-utils";
import jwt from "jsonwebtoken";

// Parâmetros fixos
const g = BigInt(7);
const N = BigInt(
  "0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7"
);

// Função para converter um Buffer para um BigInt em little-endian
const bufferToBigIntLE = (buffer) => {
  let result = BigInt(0);
  for (let i = buffer.length - 1; i >= 0; i--) {
    result = (result << BigInt(8)) + BigInt(buffer[i]);
  }
  return result;
};

// Função para converter um BigInt para um Buffer em little-endian
const bigIntToBufferLE = (num, length) => {
  let hex = num.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16));
  }
  bytes.reverse();
  while (bytes.length < length) {
    bytes.push(0);
  }
  return Buffer.from(bytes);
};

export const register = (req, res) => {
  const { email, username, password, confirmPassword } = req.body;

  if (!email) {
    return res.status(422).json({ msg: "É obrigatório inserir um email." });
  }
  if (!username) {
    return res
      .status(422)
      .json({ msg: "É obrigatório inserir um nome de usuário." });
  }
  if (!password) {
    return res.status(422).json({ msg: "É obrigatório inserir uma senha." });
  }
  if (confirmPassword != password) {
    return res.status(422).json({ msg: "As senhas não coincidem." });
  }

  db.query(
    "SELECT email, username FROM account WHERE email = ? OR username = ?",
    [email, username],
    async (error, data) => {
      if (error) {
        console.log(error);
        return res.status(500).json({
          msg: "Houve algum erro no servidor. Tente novamente em alguns instantes",
        });
      }
      if (data.length > 0) {
        if (data[0].email === email) {
          return res.status(500).json({
            msg: "Este email já está sendo utilizado.",
          });
        } else if (data[0].username === username) {
          return res.status(500).json({
            msg: "Este usuário já está sendo utilizado.",
          });
        }
      } else {
        // Gerar um salt de 32 bytes
        const salt = crypto.randomBytes(32);

        // Etapa 1: Calcular h1 = SHA1("USERNAME:PASSWORD")
        const h1 = crypto
          .createHash("sha1")
          .update(`${username.toUpperCase()}:${password.toUpperCase()}`)
          .digest();

        // Etapa 2: Calcular h2 = SHA1(salt || h1)
        const h2 = crypto
          .createHash("sha1")
          .update(Buffer.concat([salt, h1]))
          .digest();

        // Etapa 3: Converter h2 para um BigInt em ordem little-endian
        const h2Int = bufferToBigIntLE(h2);

        // Etapa 4: Calcular (g ^ h2) % N usando bigint-crypto-utils
        const verifierInt = modPow(g, h2Int, N);

        // Etapa 5: Converter o resultado para um Buffer em ordem little-endian
        const verifier = bigIntToBufferLE(verifierInt, 32);

        // Armazenar o username, email, hash e salt
        db.query(
          "INSERT INTO account SET ?",
          {
            username,
            email,
            salt: salt,
            verifier: verifier,
          },
          (insertError) => {
            if (insertError) {
              console.log(insertError);
              return res.status(500).json({
                msg: "Houve algum erro no servidor ao registrar o usuário. Tente novamente em alguns instantes",
              });
            }
            return res.status(201).json({
              msg: "Usuário registrado com sucesso.",
            });
          }
        );
      }
    }
  );
};

export const login = (req, res) => {
  const { email, username, password } = req.body;

  if (!username) {
    return res
      .status(422)
      .json({ msg: "É obrigatório inserir um nome de usuário." });
  }
  if (!password) {
    return res.status(422).json({ msg: "É obrigatório inserir uma senha." });
  }

  db.query(
    "SELECT * FROM account WHERE email = ? OR username = ?",
    [email || null, username || null],
    async (error, results) => {
      if (error) {
        console.log(error);
        return res.status(500).json({
          msg: "Houve algum erro no servidor. Tente novamente em alguns instantes.",
        });
      }

      if (results.length === 0) {
        return res.status(401).json({ msg: "Usuário não encontrado." });
      }

      const user = results[0];

      // Etapa 1: Calcular h1 = SHA1("USERNAME:PASSWORD")
      const h1 = crypto
        .createHash("sha1")
        .update(`${user.username.toUpperCase()}:${password.toUpperCase()}`)
        .digest();

      // Etapa 2: Calcular h2 = SHA1(salt || h1)
      const h2 = crypto
        .createHash("sha1")
        .update(Buffer.concat([user.salt, h1]))
        .digest();

      // Etapa 3: Converter h2 para um BigInt em ordem little-endian
      const h2Int = bufferToBigIntLE(h2);

      // Etapa 4: Calcular (g ^ h2) % N usando bigint-crypto-utils
      const verifierInt = modPow(g, h2Int, N);

      // Etapa 5: Converter o resultado para um Buffer em ordem little-endian
      const verifier = bigIntToBufferLE(verifierInt, 32);

      // Verificar se o verifier calculado é igual ao armazenado no banco de dados
      if (Buffer.compare(verifier, user.verifier) !== 0) {
        return res.status(401).json({ msg: "Senha incorreta." });
      }

      /*
      // Se chegou até aqui, o usuário está autenticado com sucesso
      return res.status(200).json({ msg: "Usuário autenticado com sucesso." });
      */

      try {
        const refreshToken = jwt.sign(
          { userId: user.id },
          process.env.REFRESH_SECRET,
          { expiresIn: "24h" }
        );
        const token = jwt.sign({ userId: user.id }, process.env.TOKEN_SECRET, {
          expiresIn: "1h",
        });
        res.status(200).json({
          msg: "Usuário logado com sucesso!",
          token,
          refreshToken,
        });
      } catch (err) {
        console.log(err);
        return res.status(500).json({
          msg: "Houve algum erro no servidor. Tente novamente em alguns instantes.",
        });
      }
    }
  );
};
