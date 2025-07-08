import Database from "better-sqlite3";
import { logger } from "./helpers/logs.js";

const log = logger("db");
const DB_NAME = "todos";
const db = new Database(":memory:", {
  verbose: log.info,
});

try {
  db.pragma("journal_mode = WAL");
  db.prepare(
    `CREATE TABLE IF NOT EXISTS ${DB_NAME} (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     text TEXT NOT NULL,
     completed INTEGER NOT NULL DEFAULT 0
   )`
  ).run();
  log.success(`Database "${DB_NAME}" initialized.`);
} catch (error) {
  log.error(`Error initializing database "${DB_NAME}":`, { error });
}

export async function addTodo(text: string) {
  log.info(`Adding TODO: ${text}`);
  const stmt = db.prepare(`INSERT INTO todos (text, completed) VALUES (?, 0)`);
  return stmt.run(text);
}

export async function listTodos() {
  log.info("Listing all TODOs...");
  const todos = db.prepare(`SELECT id, text, completed FROM todos`).all() as Array<{
    id: number;
    text: string;
    completed: number;
  }>;
  return todos.map(todo => ({
    ...todo,
    completed: Boolean(todo.completed),
  }));
}

export async function completeTodo(id: number) {
  log.info(`Completing TODO with ID: ${id}`);
  const stmt = db.prepare(`UPDATE todos SET completed = 1 WHERE id = ?`);
  return stmt.run(id);
}

export async function updateTodoText(id: number, text: string) {
  log.info(`Updating TODO with ID: ${id}`);
  const stmt = db.prepare(`UPDATE todos SET text = ? WHERE id = ?`);
  return stmt.run(text, id);
}

export async function deleteTodo(id: number) {
  log.info(`Deleting TODO with ID: ${id}`);
  const row = db.prepare(`SELECT text FROM todos WHERE id = ?`).get(id) as
    | { text: string }
    | undefined;
  if (!row) {
    log.error(`TODO with ID ${id} not found`);
    return null;
  }
  db.prepare(`DELETE FROM todos WHERE id = ?`).run(id);
  log.success(`TODO with ID ${id} deleted`);
  return row;
}
