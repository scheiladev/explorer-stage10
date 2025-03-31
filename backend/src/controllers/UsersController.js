const knex = require("../database/knex");
const { hash, compare } = require("bcryptjs");
const AppError = require("../utils/AppError");

class UsersController {
  async create(request, response) {
    const { name, email, password } = request.body;

    const checkUserExists = await knex("users").where({ email }).first();

    if (checkUserExists) {
      throw new AppError("Este e-mail já está em uso.");
    }

    if (!name) {
      throw new AppError("O nome é obrigatório.");
    }

    if (!email) {
      throw new AppError("O email é obrigatório.");
    }

    if (!password) {
      throw new AppError("A senha é obrigatória.");
    }

    const hashedPassword = await hash(password, 8);

    await knex("users").insert({
      name,
      email,
      password: hashedPassword,
    });

    return response
      .status(201)
      .json({ message: "Usuário criado com sucesso!" });
  }

  async update(request, response) {
    const { name, email, old_password, new_password } = request.body;
    const user_id = request.user.id;

    const user = await knex("users").where({id: user_id}).first();

    if (!user) {
      throw new AppError("Usuário não encontrado.");
    }

    if (!email) {
      throw new AppError("Você precisa informar seu email de cadastro.");
    }

    const checkEmailExists = await knex("users")
      .where({ email })
      .whereNot("id", Number(user_id))
      .first();

    if (checkEmailExists) {
      throw new AppError("Este e-mail já está em uso.");
    }

    user.name = name ?? user.name;
    user.email = email ?? user.email;
    
    if (new_password && !old_password) {
      throw new AppError("Você precisa informar a senha atual.");
    }
    
    if (old_password && !new_password) {
      throw new AppError("Você precisa informar a nova senha.");
    }
    
    if (old_password && new_password) {
      const checkOldPassword = await compare(old_password, user.password);
      const checkNewPassword = await compare(new_password, user.password);

      if (!checkOldPassword) {
        throw new AppError("A senha atual não confere.");
      }

      if (checkOldPassword === checkNewPassword) {
        throw new AppError("A nova senha não pode ser igual a senha atual.");
      }

      user.password = await hash(new_password, 8);
    }
    
    await knex("users")
      .where({ id: user_id })
      .update({
        name: user.name,
        email: user.email,
        password: user.password,
        updated_at: knex.fn.now(),
      });

    return response.json({ message: "Alteração realizada com sucesso!" });
  }
}

module.exports = UsersController;
