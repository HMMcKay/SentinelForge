import { Link } from 'react-router-dom';
import { EmptyState } from '../components/Status';

export default function NotFoundPage() {
  return (
    <div className="not-found">
      <EmptyState
        title="That view does not exist"
        message="The requested SentinelForge route is not available."
        action={<Link className="button button--primary button--small" to="/">Return to overview</Link>}
      />
    </div>
  );
}
