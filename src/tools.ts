import { zodToJsonSchema } from "zod-to-json-schema";
import { z } from "zod";
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
      const info = await addTodo(title);
      const structuredContent = {
        id: info.lastInsertRowid,
        title: title,
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
    },
  },
  {
    name: "list_todos",
    description:
      "List all TODO items. Returns a formatted list of all tasks with their ids, titles, and completion status.",
    inputSchema: zodToJsonSchema(ListTodosInputSchema),
    outputSchema: zodToJsonSchema(ListTodosOutputSchema),
    async execute() {
      const tools = await listTodos();
      if (!tools || tools.length === 0) {
        return { content: ["No TODOs found."], structuredContent: {} };
      }
      return {
        content: tools.map((t) => {
          return {
            type: "text",
            text: JSON.stringify(
              {
                id: t.id,
                text: t.text,
                completed: t.completed,
              },
              null,
              2
            ),
          };
        }),
        structuredContent: {
          todos: tools.map((t) => ({
            id: t.id,
            text: t.text,
            completed: t.completed,
          })),
        },
      };
    },
  },
  {
    name: "complete_todo",
    description:
      "Mark a TODO item as completed. Provide the id of the task to mark as done. Returns a confirmation message or an error if the id does not exist.",
    inputSchema: zodToJsonSchema(CompleteTodoInputSchema),
    outputSchema: zodToJsonSchema(CompleteTodoOutputSchema),
    async execute({ id }: { id: number }) {
      const info = await completeTodo(id);
      const structuredContent = {
        id,
        completed: info.changes > 0,
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
    },
  },
  {
    name: "delete_todo",
    description:
      "Delete a TODO item from the list. Provide the id of the task to delete. Returns a confirmation message or an error if the id does not exist.",
    inputSchema: zodToJsonSchema(DeleteTodoInputSchema),
    outputSchema: zodToJsonSchema(DeleteTodoOutputSchema),
    async execute({ id }: { id: number }) {
      const row = await deleteTodo(id);
      const structuredContent = {
        id,
        deleted: !!row,
      };
      if (!row) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(structuredContent, null, 2),
            },
          ],
        };
      }
      return {
        content: [`Deleted TODO: ${row.text} (id: ${id})`],
        structuredContent,
      };
    },
  },
  {
    name: "updateTodoText",
    description: "Update the text of a todo",
    inputSchema: zodToJsonSchema(UpdateTodoInputSchema),
    outputSchema: zodToJsonSchema(UpdateTodoOutputSchema),
    async execute({ id, text }: { id: number; text: string }) {
      const row = await updateTodoText(id, text);
      if (!row) {
        const message = `Todo with id ${id} not found`;
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
    },
  },
];
