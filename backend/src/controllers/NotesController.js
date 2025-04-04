const knex = require("../database/knex")
const AppError = require("../utils/AppError");

class NotesController {
  async create(request, response) {
    const { title, description, rating, tags } = request.body
    const user_id = request.user.id;

    if (!title || !description || !rating || !tags) {
      throw new AppError("Todos os campos devem ser preenchidos.");
    }

    const [note_id] = await knex("movie_notes").insert({
      title,
      description,
      rating,
      user_id
    })

    const tagsInsert = tags.map(name => {
      return {
        note_id,
        name,
        user_id
      }
    })

    await knex("movie_tags").insert(tagsInsert)

    return response
      .status(201)
      .json({ message: "Nota criada com sucesso!" });
  }

  async show(request, response) {
    const { id } = request.params

    const note = await knex("movie_notes").where({ id }).first()
    const tags = await knex("movie_tags").where({ note_id: id }).orderBy("name")

    return response.json({
      ...note,
      tags
    })
  }

  async delete(request, response) {
    const { id } = request.params

    await knex("movie_notes").where({ id }).delete()

    return response.json({ message: 'Nota excluída com sucesso!'})
  }

  async index(request, response) {
    const { title, tags } = request.query;
    const user_id = request.user.id;

    console.log(user_id)

    let notes

    if (tags) {
      const filterTags = tags.split(',').map(tag => tag.trim())

      notes = await knex("movie_tags")
        .select([
          "movie_notes.id",
          "movie_notes.title",
          "movie_notes.user_id",
        ])
        .where("movie_notes.user_id", user_id)
        .whereLike("movie_notes.title", `%${title}%`)
        .whereIn("movie_tags.name", filterTags)
        .innerJoin("movie_notes", "movie_notes.id", "movie_tags.note_id")
        .orderBy("movie_notes.title")
        
    } else {
      notes = await knex("movie_notes")
      .where({ user_id })
      .whereLike("title", `%${title}%`)
      .orderBy("title")
    }

    const userTags = await knex("movie_tags").where({ user_id })

    const notesWhithTags = notes.map(note => {
      const noteTags = userTags.filter(tag => tag.note_id === note.id)

      return {
        ...note,
        tags: noteTags
      }
    })

    return response.json(notesWhithTags)
  }
}

module.exports = NotesController
