export class AgentReadyError extends Error {
  constructor(message, exitCode = 4) {
    super(message);
    this.name = "AgentReadyError";
    this.exitCode = exitCode;
  }
}

export function usageError(message) {
  return new AgentReadyError(message, 2);
}

export function configError(message) {
  return new AgentReadyError(message, 3);
}
