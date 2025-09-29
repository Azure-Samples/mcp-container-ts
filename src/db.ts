import { z } from 'zod';
import Database from "better-sqlite3";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import { logger } from "./helpers/logs.js";

const TodoSchema = z.object({
  title: z.string().min(1).max(255).regex(/^[a-zA-Z0-9\s\-_.,!?]+$/),
  id: z.number().positive().int().optional(),
});

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
  const tracer = trace.getTracer("database");
  const span = tracer.startSpan("db.addTodo", {
    attributes: {
      "db.operation": "INSERT",
      "db.table": "todos",
      "todo.text": text,
      "todo.text_length": text.length,
    },
  });
  
  try {
    log.info(`Adding TODO: ${text}`);
    const validatedInput = TodoSchema.parse({ title: text });
    
    span.addEvent("validation.completed", {
      "input.valid": true,
      "validated.title": validatedInput.title,
    });
    
    const startTime = Date.now();
    const stmt = db.prepare(`INSERT INTO todos (text, completed) VALUES (?, 0)`);
    const result = stmt.run(validatedInput.title);
    const executionTime = Date.now() - startTime;
    
    span.setAttributes({
      "db.execution_time_ms": executionTime,
      "db.last_insert_rowid": result.lastInsertRowid as number,
      "db.changes": result.changes,
      "operation.success": true,
    });
    
    span.addEvent("db.insert_completed", {
      "todo.id": result.lastInsertRowid as number,
      "execution_time_ms": executionTime,
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: "TODO added to database",
    });
    
    return result;
  } catch (error) {
    span.addEvent("db.insert_error", {
      "error.message": error instanceof Error ? error.message : String(error),
      "error.name": error instanceof Error ? error.name : "unknown",
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

export async function listTodos() {
  const tracer = trace.getTracer("database");
  const span = tracer.startSpan("db.listTodos", {
    attributes: {
      "db.operation": "SELECT",
      "db.table": "todos",
    },
  });
  
  try {
    log.info("Listing all TODOs...");
    
    const startTime = Date.now();
    const todos = db.prepare(`SELECT id, text, completed FROM todos`).all() as Array<{
      id: number;
      text: string;
      completed: number;
    }>;
    const executionTime = Date.now() - startTime;
    
    const completedCount = todos.filter(t => t.completed).length;
    const pendingCount = todos.length - completedCount;
    
    span.setAttributes({
      "db.execution_time_ms": executionTime,
      "db.rows_returned": todos.length,
      "todos.total_count": todos.length,
      "todos.completed_count": completedCount,
      "todos.pending_count": pendingCount,
      "operation.success": true,
    });
    
    span.addEvent("db.select_completed", {
      "rows_returned": todos.length,
      "execution_time_ms": executionTime,
      "completed_todos": completedCount,
      "pending_todos": pendingCount,
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: `Retrieved ${todos.length} TODOs from database`,
    });
    
    return todos.map(todo => ({
      ...todo,
      completed: Boolean(todo.completed),
    }));
  } catch (error) {
    span.addEvent("db.select_error", {
      "error.message": error instanceof Error ? error.message : String(error),
      "error.name": error instanceof Error ? error.name : "unknown",
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

export async function completeTodo(id: number) {
  const tracer = trace.getTracer("database");
  const span = tracer.startSpan("db.completeTodo", {
    attributes: {
      "db.operation": "UPDATE",
      "db.table": "todos",
      "todo.id": id,
    },
  });
  
  try {
    log.info(`Completing TODO with ID: ${id}`);
    const validatedInput = z.number().positive().int().parse(id);
    
    span.addEvent("validation.completed", {
      "input.valid": true,
      "validated.id": validatedInput,
    });
    
    const startTime = Date.now();
    const stmt = db.prepare(`UPDATE todos SET completed = 1 WHERE id = ?`);
    const result = stmt.run(validatedInput);
    const executionTime = Date.now() - startTime;
    
    span.setAttributes({
      "db.execution_time_ms": executionTime,
      "db.changes": result.changes,
      "operation.success": result.changes > 0,
    });
    
    if (result.changes > 0) {
      span.addEvent("db.update_completed", {
        "todo.id": validatedInput,
        "execution_time_ms": executionTime,
        "rows_affected": result.changes,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "TODO marked as completed",
      });
    } else {
      span.addEvent("db.no_rows_affected", {
        "todo.id": validatedInput,
        "execution_time_ms": executionTime,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "No TODO found with given ID",
      });
    }
    
    return result;
  } catch (error) {
    span.addEvent("db.update_error", {
      "error.message": error instanceof Error ? error.message : String(error),
      "error.name": error instanceof Error ? error.name : "unknown",
      "todo.id": id,
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

export async function updateTodoText(id: number, text: string) {
  const tracer = trace.getTracer("database");
  const span = tracer.startSpan("db.updateTodoText", {
    attributes: {
      "db.operation": "UPDATE",
      "db.table": "todos",
      "todo.id": id,
      "todo.new_text": text,
      "todo.text_length": text.length,
    },
  });
  
  try {
    log.info(`Updating TODO with ID: ${id}`);
    const validatedInput = TodoSchema.parse({ title: text, id });
    
    span.addEvent("validation.completed", {
      "input.valid": true,
      "validated.id": validatedInput.id,
      "validated.title": validatedInput.title,
    });
    
    const startTime = Date.now();
    const stmt = db.prepare(`UPDATE todos SET text = ? WHERE id = ?`);
    const result = stmt.run(validatedInput.title, validatedInput.id);
    const executionTime = Date.now() - startTime;
    
    span.setAttributes({
      "db.execution_time_ms": executionTime,
      "db.changes": result.changes,
      "operation.success": result.changes > 0,
    });
    
    if (result.changes > 0) {
      span.addEvent("db.update_completed", {
        "todo.id": validatedInput.id,
        "todo.new_text": validatedInput.title,
        "execution_time_ms": executionTime,
        "rows_affected": result.changes,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "TODO text updated successfully",
      });
    } else {
      span.addEvent("db.no_rows_affected", {
        "todo.id": validatedInput.id,
        "execution_time_ms": executionTime,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "No TODO found with given ID",
      });
    }
    
    return result;
  } catch (error) {
    span.addEvent("db.update_error", {
      "error.message": error instanceof Error ? error.message : String(error),
      "error.name": error instanceof Error ? error.name : "unknown",
      "todo.id": id,
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}

export async function deleteTodo(id: number) {
  const tracer = trace.getTracer("database");
  const span = tracer.startSpan("db.deleteTodo", {
    attributes: {
      "db.operation": "DELETE",
      "db.table": "todos",
      "todo.id": id,
    },
  });
  
  try {
    log.info(`Deleting TODO with ID: ${id}`);
    const validatedInput = z.number().positive().int().parse(id);
    
    span.addEvent("validation.completed", {
      "input.valid": true,
      "validated.id": validatedInput,
    });
    
    // First, get the TODO to return its text
    const selectStartTime = Date.now();
    const row = db.prepare(`SELECT text FROM todos WHERE id = ?`).get(id) as
      | { text: string }
      | undefined;
    const selectTime = Date.now() - selectStartTime;
    
    span.addEvent("db.select_for_delete", {
      "todo.id": id,
      "execution_time_ms": selectTime,
      "todo.found": !!row,
    });
    
    if (!row) {
      span.addEvent("db.todo_not_found", {
        "todo.id": id,
      });
      span.setStatus({
        code: SpanStatusCode.OK,
        message: "TODO not found",
      });
      log.error(`TODO with ID ${id} not found`);
      return null;
    }
    
    span.setAttributes({
      "todo.text": row.text,
      "todo.text_length": row.text.length,
    });
    
    // Delete the TODO
    const deleteStartTime = Date.now();
    const deleteResult = db.prepare(`DELETE FROM todos WHERE id = ?`).run(validatedInput);
    const deleteTime = Date.now() - deleteStartTime;
    
    span.setAttributes({
      "db.select_execution_time_ms": selectTime,
      "db.delete_execution_time_ms": deleteTime,
      "db.total_execution_time_ms": selectTime + deleteTime,
      "db.changes": deleteResult.changes,
      "operation.success": true,
    });
    
    span.addEvent("db.delete_completed", {
      "todo.id": validatedInput,
      "todo.text": row.text,
      "execution_time_ms": deleteTime,
      "rows_affected": deleteResult.changes,
    });
    
    span.setStatus({
      code: SpanStatusCode.OK,
      message: "TODO deleted successfully",
    });
    
    log.success(`TODO with ID ${validatedInput} deleted`);
    return row;
  } catch (error) {
    span.addEvent("db.delete_error", {
      "error.message": error instanceof Error ? error.message : String(error),
      "error.name": error instanceof Error ? error.name : "unknown",
      "todo.id": id,
    });
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  } finally {
    span.end();
  }
}
