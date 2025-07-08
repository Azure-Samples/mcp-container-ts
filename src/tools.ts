import {
  addTodo,
  listTodos,
  completeTodo,
  deleteTodo,
  updateTodoText,
} from "./db.js";

export const TodoTools = [
  {
    name: "addTodo",
    description:
      "Add a new TODO item to the list. Provide a text for the task you want to add. Returns a confirmation message with the new TODO id.",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string" },
      },
      required: ["text"],
    },
    outputSchema: { type: "string" },
    async execute({ text }: { text: string }) {
      const info = await addTodo(text);
      return `Added TODO: ${text} (id: ${info.lastInsertRowid})`;
    },
  },
  {
    name: "listTodos",
    description:
      "List all TODO items. Returns a formatted list of all tasks with their ids, texts, and completion status.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
    outputSchema: { type: "string" },
    async execute() {
      const tools = await listTodos();
      if (!tools || tools.length === 0) {
        return "No TODOs found.";
      }
      return tools
        .map((t) => `${t.id}. ${t.text} [${t.completed ? "x" : " "}]`)
        .join("\n");
    },
  },
  {
    name: "completeTodo",
    description:
      "Mark a TODO item as completed. Provide the id of the task to mark as done. Returns a confirmation message or an error if the id does not exist.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number" },
      },
      required: ["id"],
    },
    outputSchema: { type: "string" },
    async execute({ id }: { id: number }) {
      const info = await completeTodo(id);
      if (info.changes === 0) {
        return `TODO with id ${id} not found.`;
      }
      return `Marked TODO ${id} as completed.`;
    },
  },
  {
    name: "deleteTodo",
    description:
      "Delete a TODO item from the list. Provide the id of the task to delete. Returns a confirmation message or an error if the id does not exist.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number" },
      },
      required: ["id"],
    },
    outputSchema: { type: "string" },
    async execute({ id }: { id: number }) {
      const row = await deleteTodo(id);
      if (!row) {
        return `TODO with id ${id} not found.`;
      }
      return `Deleted TODO: ${row.text} (id: ${id})`;
    },
  },
  {
    name: "updateTodoText",
    description: "Update the text of a todo",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "number" },
        text: { type: "string" },
      },
      required: ["id"],
    },
    outputSchema: { type: "string" },
    async execute({ id, text }: { id: number; text: string }) {
      const row = await updateTodoText(id, text);
      if (!row) {
        return `TODO with id ${id} not found.`;
      }
      return `Updated text for todo with id ${id} to "${text}"`;
    },
  },
];
