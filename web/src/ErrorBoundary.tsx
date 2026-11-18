// A render error inside one region of a page shows one line in its place
// ("这部分出错了" + the error + 重试) instead of taking down the page: the
// navigation and the other regions keep working.

import { Button } from "antd";
import { Component, type ReactNode } from "react";

export class ErrorBoundary extends Component<{ children: ReactNode; testId?: string }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: unknown) {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }
  componentDidCatch(error: unknown) {
    console.error("render error in a page region", error);
  }
  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div role="alert" className="region-error" data-testid={this.props.testId ?? "region-error"} style={{ padding: "8px 0", overflowWrap: "anywhere" }}>
        <span className="status-text">这部分出错了</span>
        {error.message ? <span className="muted">：{error.message}</span> : null}{" "}
        <Button size="small" type="link" style={{ padding: 0 }} onClick={() => this.setState({ error: null })}>
          重试
        </Button>
      </div>
    );
  }
}
