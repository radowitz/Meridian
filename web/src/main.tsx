import React from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider, theme } from "antd";
import zhCN from "antd/locale/zh_CN";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: "#c9852a",
          colorBgBase: "#10161c",
          colorTextBase: "#e7eef6",
          borderRadius: 8,
          fontFamily: '"Noto Sans SC", "Source Han Sans SC", "Segoe UI", sans-serif',
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>,
);
