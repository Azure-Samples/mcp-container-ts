import { addTodo, listTodos, completeTodo, deleteTodo } from './db.js';

export const TodoTools = [
  {
    name: 'add_todo',
    description:
      'Add a new TODO item to the list. Provide a title for the task you want to add. Returns a confirmation message with the new TODO id.',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
      },
      required: ['title'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              text: { type: 'string' },
            },
            required: ['type', 'text'],
          },
        },
      },
      required: ['content'],
    },
    async execute({ title }: { title: string }) {
      const info = await addTodo(title);
      return {
        content: [
          {
            type: 'text',
            text: `Added TODO: ${title} (id: ${info.id})`,
          },
        ],
      };
    },
  },
  {
    name: 'list_todos',
    description:
      'List all TODO items. Returns a formatted list of all tasks with their ids, titles, and completion status.',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
    outputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              text: { type: 'string' },
            },
            required: ['type', 'text'],
          },
        },
      },
      required: ['content'],
    },
    async execute() {
      const tools = await listTodos();
      if (!tools || tools.length === 0) {
        return {
          content: [{ type: 'text', text: 'No TODOs found.' }],
        };
      }
      return {
        content: [
          {
            type: 'text',
            text: tools
              .map((t) => `${t.id}. ${t.title} [${t.completed ? 'x' : ' '}]`)
              .join('\n'),
          },
        ],
      };
    },
  },
  {
    name: 'complete_todo',
    description:
      'Mark a TODO item as completed. Provide the id of the task to mark as done. Returns a confirmation message or an error if the id does not exist.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number' },
      },
      required: ['id'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              text: { type: 'string' },
            },
            required: ['type', 'text'],
          },
        },
      },
      required: ['content'],
    },
    async execute({ id }: { id: number }) {
      const info = await completeTodo(id);
      if (info.changes === 0) {
        return {
          content: [{ type: 'text', text: `TODO with id ${id} not found.` }],
        };
      }
      return {
        content: [{ type: 'text', text: `Marked TODO ${id} as completed.` }],
      };
    },
  },
  {
    name: 'delete_todo',
    description:
      'Delete a TODO item from the list. Provide the id of the task to delete. Returns a confirmation message or an error if the id does not exist.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number' },
      },
      required: ['id'],
    },
    outputSchema: {
      type: 'object',
      properties: {
        content: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              text: { type: 'string' },
            },
            required: ['type', 'text'],
          },
        },
      },
      required: ['content'],
    },
    async execute({ id }: { id: number }) {
      const row = await deleteTodo(id);
      if (!row) {
        return {
          content: [{ type: 'text', text: `TODO with id ${id} not found.` }],
        };
      }
      return {
        content: [
          {
            type: 'text',
            text: `Deleted TODO: ${row.title} (id: ${id})`,
          },
        ],
      };
    },
  },
];
