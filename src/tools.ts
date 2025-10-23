import { zodToJsonSchema } from "zod-to-json-schema";
import { z } from "zod";
import { trace, SpanStatusCode } from "@opentelemetry/api";
import {
  addTodo,
  listTodos,
  completeTodo,
  deleteTodo,
  updateTodoText,
} from "./db.js";

// Zod schemas for input validation
const AddTodoInputSchema = z.object({
  title: z.string(),
});

const CompleteTodoInputSchema = z.object({
  id: z.number(),
});

const DeleteTodoInputSchema = z.object({
  id: z.number(),
});

const UpdateTodoInputSchema = z.object({
  id: z.number(),
  text: z.string(),
});

const ListTodosInputSchema = z.object({});

// output schemas
const AddTodoOutputSchema = z.object({
  id: z.number(),
  title: z.string(),
});

const CompleteTodoOutputSchema = z.object({
  id: z.number(),
  completed: z.boolean(),
});

const DeleteTodoOutputSchema = z.object({
  id: z.number(),
  deleted: z.boolean(),
});

const UpdateTodoOutputSchema = z.object({
  id: z.number(),
});

const ListTodosOutputSchema = z.object({
  todos: z.array(
    z.object({
      id: z.number(),
      text: z.string(),
      completed: z.boolean(),
    })
  ),
});

// Define the tools

export const TodoTools = [
  {
    name: "add_todo",
    description:
      "Add a new TODO item to the list. Provide a title for the task you want to add. Returns a confirmation message with the new TODO id.",
    inputSchema: zodToJsonSchema(AddTodoInputSchema),
    outputSchema: zodToJsonSchema(AddTodoOutputSchema),
    async execute({ title }: { title: string }) {
      const tracer = trace.getTracer("todo-tools");
      const span = tracer.startSpan("add_todo", {
        attributes: {
          "todo.title": title,
          "todo.title_length": title.length,
        },
      });

      try {
        const info = await addTodo(title);
        const structuredContent = {
          id: info.lastInsertRowid,
          title: title,
        };

        span.setAttributes({
          "todo.id": info.lastInsertRowid as number,
          "operation.success": true,
        });

        span.addEvent("todo.created", {
          "todo.id": info.lastInsertRowid as number,
          "todo.title": title,
        });

        span.setStatus({
          code: SpanStatusCode.OK,
          message: "TODO added successfully",
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(structuredContent, null, 2),
            },
          ],
          structuredContent,
        };
      } catch (error) {
        span.addEvent("todo.creation_error", {
          "error.message":
            error instanceof Error ? error.message : String(error),
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error instanceof Error ? error.message : String(error),
        });
        throw error;
      } finally {
        span.end();
      }
    },
  },
  {
    name: "list_todos",
    description:
      "List all TODO items. Returns a formatted list of all tasks with their ids, titles, and completion status.",
    inputSchema: zodToJsonSchema(ListTodosInputSchema),
    outputSchema: zodToJsonSchema(ListTodosOutputSchema),
    async execute() {
      const tracer = trace.getTracer("todo-tools");
      const span = tracer.startSpan("list_todos");

      try {
        const todos = await listTodos();

        span.setAttributes({
          "todos.count": todos.length,
          "todos.completed_count": todos.filter((t) => t.completed).length,
          "todos.pending_count": todos.filter((t) => !t.completed).length,
        });

        if (!todos || todos.length === 0) {
          span.addEvent("todos.empty_list");
          span.setStatus({
            code: SpanStatusCode.OK,
            message: "No TODOs found",
          });
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ todos: [] }, null, 2),
              },
            ],
            structuredContent: {
              todos: [],
            },
          };
        }

        span.addEvent("todos.listed", {
          count: todos.length,
          completed: todos.filter((t) => t.completed).length,
        });

        span.setStatus({
          code: SpanStatusCode.OK,
          message: `Listed ${todos.length} TODOs`,
        });

        const structuredContent = {
          todos,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(structuredContent, null, 2),
            },
          ],
          structuredContent,
        };
      } catch (error) {
        span.addEvent("todos.list_error", {
          "error.message":
            error instanceof Error ? error.message : String(error),
        });
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: error instanceof Error ? error.message : String(error),
        });
        throw error;
      } finally {
        span.end();
      }
    },
  },
  {
    name: "complete_todo",
    description:
      "Mark a TODO item as completed. Provide the id of the task to mark as done. Returns a confirmation message or an error if the id does not exist.",
    inputSchema: zodToJsonSchema(CompleteTodoInputSchema),
    outputSchema: zodToJsonSchema(CompleteTodoOutputSchema),
    async execute({ id }: { id: number }) {
      const tracer = trace.getTracer("todo-tools");
      const span = tracer.startSpan("complete_todo", {
        attributes: {
          "todo.id": id,
        },
      });

      try {
        const info = await completeTodo(id);
        const wasCompleted = info.changes > 0;
        const structuredContent = {
          id,
          completed: wasCompleted,
        };

        span.setAttributes({
          "operation.success": wasCompleted,
          "database.changes": info.changes,
        });

        if (wasCompleted) {
          span.addEvent("todo.completed", {
            "todo.id": id,
          });
          span.setStatus({
            code: SpanStatusCode.OK,
            message: "TODO marked as completed",
          });
        } else {
          span.addEvent("todo.not_found", {
            "todo.id": id,
          });
          span.setStatus({
            code: SpanStatusCode.OK,
            message: "TODO not found or already completed",
          });
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(structuredContent, null, 2),
            },
          ],
          structuredContent,
        };
      } catch (error) {
        span.addEvent("todo.completion_error", {
          "error.message":
            error instanceof Error ? error.message : String(error),
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
    },
  },
  {
    name: "delete_todo",
    description:
      "Delete a TODO item from the list. Provide the id of the task to delete. Returns a confirmation message or an error if the id does not exist.",
    inputSchema: zodToJsonSchema(DeleteTodoInputSchema),
    outputSchema: zodToJsonSchema(DeleteTodoOutputSchema),
    async execute({ id }: { id: number }) {
      const tracer = trace.getTracer("todo-tools");
      const span = tracer.startSpan("delete_todo", {
        attributes: {
          "todo.id": id,
        },
      });

      try {
        const row = await deleteTodo(id);
        const wasDeleted = !!row;
        const structuredContent = {
          id,
          deleted: wasDeleted,
        };

        span.setAttributes({
          "operation.success": wasDeleted,
        });

        if (!row) {
          span.addEvent("todo.not_found", {
            "todo.id": id,
          });
          span.setStatus({
            code: SpanStatusCode.OK,
            message: "TODO not found",
          });
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(structuredContent, null, 2),
              },
            ],
          };
        }

        span.setAttributes({
          "todo.text": row.text,
          "todo.text_length": row.text.length,
        });

        span.addEvent("todo.deleted", {
          "todo.id": id,
          "todo.text": row.text,
        });

        span.setStatus({
          code: SpanStatusCode.OK,
          message: "TODO deleted successfully",
        });

        return {
          content: [`Deleted TODO: ${row.text} (id: ${id})`],
          structuredContent,
        };
      } catch (error) {
        span.addEvent("todo.deletion_error", {
          "error.message":
            error instanceof Error ? error.message : String(error),
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
    },
  },
  {
    name: "updateTodoText",
    description: "Update the text of a todo",
    inputSchema: zodToJsonSchema(UpdateTodoInputSchema),
    outputSchema: zodToJsonSchema(UpdateTodoOutputSchema),
    async execute({ id, text }: { id: number; text: string }) {
      const tracer = trace.getTracer("todo-tools");
      const span = tracer.startSpan("update_todo_text", {
        attributes: {
          "todo.id": id,
          "todo.new_text": text,
          "todo.text_length": text.length,
        },
      });

      try {
        const row = await updateTodoText(id, text);

        if (!row) {
          const message = `Todo with id ${id} not found`;

          span.addEvent("todo.not_found", {
            "todo.id": id,
          });

          span.setStatus({
            code: SpanStatusCode.OK,
            message: "TODO not found",
          });

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({ isError: true, message }, null, 2),
              },
            ],
            structuredContent: {
              isError: true,
              message,
              id,
            },
          };
        }

        span.setAttributes({
          "operation.success": true,
        });

        span.addEvent("todo.text_updated", {
          "todo.id": id,
          "todo.new_text": text,
        });

        span.setStatus({
          code: SpanStatusCode.OK,
          message: "TODO text updated successfully",
        });

        const structuredContent = {
          id,
        };
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(structuredContent, null, 2),
            },
          ],
          structuredContent,
        };
      } catch (error) {
        span.addEvent("todo.update_error", {
          "error.message":
            error instanceof Error ? error.message : String(error),
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
    },
  },
];
