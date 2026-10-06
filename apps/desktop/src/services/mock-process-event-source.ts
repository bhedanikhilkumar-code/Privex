import { EventEmitter } from 'events';
import {
  IProcessEventSource,
  ProcessCreationEvent,
  ProcessEventSourceStatus
} from '../types/desktop.types';

export class MockProcessEventSource extends EventEmitter implements IProcessEventSource {
  private state: 'INITIALIZING' | 'ACTIVE' | 'ERROR' | 'STOPPED' = 'STOPPED';
  private lastError?: string;
  private eventsObserved = 0;
  private processCreatedCallback?: (event: ProcessCreationEvent) => void;
  public startCallCount = 0;
  public stopCallCount = 0;

  public getStatus(): ProcessEventSourceStatus {
    return {
      state: this.state,
      sourceName: 'MOCK',
      lastError: this.lastError,
      eventsObserved: this.eventsObserved
    };
  }

  public onProcessCreated(callback: (event: ProcessCreationEvent) => void): void {
    this.processCreatedCallback = callback;
  }

  public async start(): Promise<void> {
    this.startCallCount++;
    this.state = 'ACTIVE';
    this.lastError = undefined;
    this.emit('active');
  }

  public async stop(): Promise<void> {
    this.stopCallCount++;
    this.state = 'STOPPED';
    this.emit('stopped');
  }

  public async dispose(): Promise<void> {
    await this.stop();
    this.processCreatedCallback = undefined;
    this.removeAllListeners();
  }

  /**
   * Simulates an inbound process creation event from the OS.
   */
  public emitEvent(event: ProcessCreationEvent): void {
    if (this.state !== 'ACTIVE') return;
    this.eventsObserved++;
    if (this.processCreatedCallback) {
      this.processCreatedCallback(event);
    }
    this.emit('processCreated', event);
  }

  /**
   * Simulates an unexpected failure in the event source.
   */
  public simulateFailure(err: Error): void {
    this.state = 'ERROR';
    this.lastError = err.message;
    this.emit('error', err);
  }
}
