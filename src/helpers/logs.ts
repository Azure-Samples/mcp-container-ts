import chalk, { ChalkInstance } from 'chalk';
import debug from 'debug';

debug.enable('mcp:*'); // Enable all debug logs

export const logger = (namespace: string) => {
  const dbg = debug('mcp:' + namespace);
  const log = (colorize: ChalkInstance, ...args: any[]) => {
    const timestamp = new Date().toISOString();
    const formattedArgs = [timestamp, ...args].map((arg) => {
      if (typeof arg === 'object') {
        return JSON.stringify(arg, null, 2);
      }
      return arg;
    });
    dbg(colorize(formattedArgs.join(' ')));
  };

  return {
    info(...args: any[]) {
      log(chalk.cyan, ...args);
    },
    success(...args: any[]) {
      log(chalk.green, ...args);
    },
    warn(...args: any[]) {
      log(chalk.yellow, ...args);
    },
    error(...args: any[]) {
      log(chalk.red, ...args);
    },
  };
};
