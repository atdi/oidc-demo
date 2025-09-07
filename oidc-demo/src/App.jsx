import { useState, useEffect } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [count, setCount] = useState(0);
  const [apiData, setApiData] = useState(null);
  const [apiLoading, setApiLoading] = useState(false);
  const [error, setError] = useState(null);

  // Check if user is authenticated on component mount
  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const response = await fetch('http://localhost:8081/api/auth/user', {
        credentials: 'include',
      });
      
      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
      }
    } catch (err) {
      console.error('Not authenticated', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = () => {
    // Redirect to Spring Boot OAuth2 login endpoint
    window.location.href = 'http://localhost:8081/oauth2/authorization/external';
  };

  const handleLogout = async () => {
    try {
      await fetch('http://localhost:8081/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
      setUser(null);
      setApiData(null);
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  // Function to make authenticated API calls using cookies
  const callAPI = async (url, options = {}) => {
    const response = await fetch(url, {
      ...options,
      credentials: 'include', // This ensures cookies are sent with the request
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  };

  // Example API call function
  const fetchData = async () => {
    setApiLoading(true);
    setError(null);
    
    try {
      const data = await callAPI('http://localhost:8081/api/data');
      setApiData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setApiLoading(false);
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return (
      <div>
        <h1>Please log in</h1>
        <button onClick={handleLogin}>Log in with Keycloak</button>
      </div>
    );
  }

  return (
    <>
      <div>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      
      {/* User info */}
      <div className="user-info">
        <p>Welcome, {user.name || 'User'}!</p>
        <p>Email: {user.email}</p>
        <button onClick={handleLogout}>Log out</button>
      </div>

      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        
        {/* API interaction */}
        <div style={{ marginTop: '20px' }}>
          <button onClick={fetchData} disabled={apiLoading}>
            {apiLoading ? 'Loading...' : 'Fetch API Data'}
          </button>
          
          {error && (
            <div style={{ color: 'red', marginTop: '10px' }}>
              Error: {error}
            </div>
          )}
          
          {apiData && (
            <div style={{ marginTop: '10px' }}>
              <h3>API Response:</h3>
              <pre style={{ textAlign: 'left', background: '#f5f5f5', padding: '10px' }}>
                {JSON.stringify(apiData, null, 2)}
              </pre>
            </div>
          )}
        </div>

        <p>
          Edit <code>src/App.jsx</code> and save to test HMR
        </p>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </>
  )
}

export default App
