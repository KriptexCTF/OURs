import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";

import { Scanner } from "./components/Scanner";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Scanner></Scanner>
  </StrictMode>,
);
