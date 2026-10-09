import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Icon } from './Icon';

interface State {
  error?: Error;
}

export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = {};

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('SentinelForge UI render failure', { error, componentStack: info.componentStack });
  }

  render() {
    if (this.state.error) {
      return (
        <main className="fatal-error">
          <Icon name="warning" size={36} />
          <h1>The dashboard could not render</h1>
          <p>{this.state.error.message}</p>
          <button className="button button--primary" onClick={() => window.location.reload()} type="button">
            Reload SentinelForge
          </button>
        </main>
      );
    }
    return this.props.children;
  }
}
