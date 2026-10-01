export enum MessageType {
  GET_TAB_STATUS = 'GET_TAB_STATUS',
  TAB_STATUS_RESPONSE = 'TAB_STATUS_RESPONSE',
  REPORT_DOM_SIGNALS = 'REPORT_DOM_SIGNALS',
  REQUEST_OVERRIDE = 'REQUEST_OVERRIDE',
  OVERRIDE_RESPONSE = 'OVERRIDE_RESPONSE',
  ANALYZE_URL_MANUAL = 'ANALYZE_URL_MANUAL',
  ANALYZE_URL_RESPONSE = 'ANALYZE_URL_RESPONSE',
  GET_SETTINGS = 'GET_SETTINGS',
  SETTINGS_RESPONSE = 'SETTINGS_RESPONSE',
  UPDATE_SETTINGS = 'UPDATE_SETTINGS',
  CLEAR_ALL_DATA = 'CLEAR_ALL_DATA',
  OPERATION_SUCCESS = 'OPERATION_SUCCESS'
}

export interface ExtensionMessage<T = any> {
  id: string;
  type: MessageType;
  payload: T;
  timestamp: number;
}

export function createMessage<T>(type: MessageType, payload: T): ExtensionMessage<T> {
  return {
    id: `msg-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    type,
    payload,
    timestamp: Date.now()
  };
}

/**
 * Validates untrusted inbound message objects against schema invariants.
 * Rejects unknown message types, oversized payloads (>64KB), and malformed structures.
 */
export function validateInboundMessage(raw: any): { valid: boolean; error?: string; message?: ExtensionMessage } {
  if (!raw || typeof raw !== 'object') {
    return { valid: false, error: 'Malformed message: not an object' };
  }

  const { id, type, payload } = raw;

  if (typeof id !== 'string' || id.length === 0 || id.length > 100) {
    return { valid: false, error: 'Invalid or missing message ID' };
  }

  if (typeof type !== 'string' || !Object.values(MessageType).includes(type as MessageType)) {
    return { valid: false, error: `Unauthorized or unknown message type: ${type}` };
  }

  // Prevent oversized payloads / memory exhaustion attacks
  try {
    const serialized = JSON.stringify(payload);
    if (serialized && serialized.length > 65536) {
      return { valid: false, error: 'Payload exceeds 64KB security limit' };
    }
  } catch {
    return { valid: false, error: 'Non-serializable payload' };
  }

  return {
    valid: true,
    message: raw as ExtensionMessage
  };
}
