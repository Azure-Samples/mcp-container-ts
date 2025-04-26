import dotenv from 'dotenv';
dotenv.config();

import pg from 'pg';
import { logger } from './helpers/logs.js';

const log = logger('db');
const DB_NAME = 'todos';

const pool = new pg.Pool({
  host: process.env.POSTGRES_HOST || 'postgres',
  port: process.env.POSTGRES_PORT ? parseInt(process.env.POSTGRES_PORT) : 5432,
  user: process.env.POSTGRES_USER || 'postgres',
  password: process.env.POSTGRES_PASSWORD || 'postgres',
  database: process.env.POSTGRES_DATABASE || 'todos',
});

async function init() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS ${DB_NAME} (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      completed BOOLEAN NOT NULL DEFAULT FALSE
    )`);
    log.success(`Database "${DB_NAME}" initialized.`);
  }
  catch (error) {
    log.error(`Error initializing database "${DB_NAME}":`, {error});
  }
}
init();

export async function addTodo(title: string) {
  log.info(`Adding TODO: ${title}`);
  const result = await pool.query(
    `INSERT INTO todos (title, completed) VALUES ($1, FALSE) RETURNING *`,
    [title]
  );
  return result.rows[0];
}

export async function listTodos() {
  log.info('Listing all TODOs...');
  const result = await pool.query(`SELECT id, title, completed FROM todos`);
  return result.rows as Array<{
    id: number;
    title: string;
    completed: boolean;
  }>;
}

export async function completeTodo(id: number) {
  log.info(`Completing TODO with ID: ${id}`);
  const result = await pool.query(
    `UPDATE todos SET completed = TRUE WHERE id = $1 RETURNING *`,
    [id]
  );
  return { changes: result.rowCount };
}

export async function deleteTodo(id: number) {
  log.info(`Deleting TODO with ID: ${id}`);
  const rowResult = await pool.query(`SELECT title FROM todos WHERE id = $1`, [id]);
  const row = rowResult.rows[0];
  if (!row) {
    log.error(`TODO with ID ${id} not found`);
    return null;
  }
  await pool.query(`DELETE FROM todos WHERE id = $1`, [id]);
  log.success(`TODO with ID ${id} deleted`);
  return row;
}
