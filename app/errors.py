"""
Error Handling Module.

Provides custom error pages and JSON error responses for common HTTP status codes.
Prevents leaking internal stack traces in production responses.
"""

from flask import jsonify, render_template, request
from flask_wtf.csrf import CSRFError


def register_error_handlers(app):
    """Registers standard HTTP error handlers on the Flask application."""
    
    def prefers_json():
        """Returns True if the client expects a JSON response."""
        return (
            request.is_json
            or request.path.startswith("/api/")
            or request.path.startswith("/health")
            or request.accept_mimetypes.best == "application/json"
        )

    @app.errorhandler(400)
    def bad_request(error):
        if prefers_json():
            return jsonify({"error": "Bad Request", "message": str(error)}), 400
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(404)
    def not_found(error):
        if prefers_json():
            return jsonify({"error": "Not Found", "message": "The requested resource was not found."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        if prefers_json():
            return jsonify({"error": "Method Not Allowed", "message": "HTTP method not allowed on this endpoint."}), 405
        return render_template("errors/400.html", error="Method Not Allowed"), 405

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        if prefers_json():
            return jsonify({"error": "CSRF Token Invalid", "message": error.description}), 400
        return render_template("errors/csrf_error.html", reason=error.description), 400

    @app.errorhandler(500)
    def internal_error(error):
        # In a real app we'd log the exception details to an audit logger
        app.logger.error(f"Internal Server Error: {error}")
        if prefers_json():
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
        return render_template("errors/500.html"), 500
