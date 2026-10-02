import { contextBridge, ipcRenderer, IpcRendererEvent } from 'electron';
import { createDesktopSecurityApi } from './preload';
import { IPC_INVOKE_CHANNELS, IPC_EVENT_CHANNELS } from '../ipc/ipc-channels';

const ALLOWED_INVOKE_CHANNELS = new Set<string>(IPC_INVOKE_CHANNELS);
const ALLOWED_EVENT_CHANNELS = new Set<string>(IPC_EVENT_CHANNELS);

const safeIpcRenderer = {
  invoke: (channel: string, ...args: any[]): Promise<any> => {
    if (!ALLOWED_INVOKE_CHANNELS.has(channel)) {
      return Promise.reject(new Error(`IPC_CHANNEL_FORBIDDEN: Channel "${channel}" is not whitelisted`));
    }
    return ipcRenderer.invoke(channel, ...args);
  },
  on: (channel: string, listener: (...args: any[]) => void): void => {
    if (!ALLOWED_EVENT_CHANNELS.has(channel)) {
      throw new Error(`IPC_EVENT_CHANNEL_FORBIDDEN: Channel "${channel}" is not whitelisted`);
    }
    ipcRenderer.on(channel, listener as (event: IpcRendererEvent, ...args: any[]) => void);
  },
  removeListener: (channel: string, listener: (...args: any[]) => void): void => {
    if (!ALLOWED_EVENT_CHANNELS.has(channel)) {
      return;
    }
    ipcRenderer.removeListener(channel, listener as (event: IpcRendererEvent, ...args: any[]) => void);
  }
};

const api = createDesktopSecurityApi(safeIpcRenderer);

contextBridge.exposeInMainWorld('desktopSecurity', Object.freeze(api));
