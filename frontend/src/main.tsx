import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LiveProvider } from './context/LiveContext';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <LiveProvider>
          <App />
        </LiveProvider>
      </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>,
);
