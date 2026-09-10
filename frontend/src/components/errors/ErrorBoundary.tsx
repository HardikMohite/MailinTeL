import React from 'react';
import { ServerCrash } from 'lucide-react';
import { FullPageError } from './FullPageError';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

/**
 * Catches render/lifecycle errors anywhere below it. Deliberately wrapped
 * only around <main> in App.tsx (not Sidebar/Header) so navigation stays
 * usable even if a single view crashes.
 */
export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    // Full stack goes to the console in dev only — never rendered to the user.
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.error('ErrorBoundary caught an error:', error, errorInfo.componentStack);
    } else {
      // eslint-disable-next-line no-console
      console.error('An unexpected UI error occurred.');
    }
  }

  private handleReload = (): void => {
    window.location.reload();
  };

  render(): React.ReactNode {
    if (this.state.hasError) {
      return (
        <FullPageError
          title="Something went wrong on our end"
          message="This view hit an unexpected error. Reloading usually fixes it."
          icon={ServerCrash}
          tone="critical"
          actionLabel="Reload"
          onAction={this.handleReload}
          technicalDetail={
            import.meta.env.DEV && this.state.error ? this.state.error.message : undefined
          }
        />
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;
