(function () {
  function normalizeMessage(value) {
    if (typeof value !== 'string') {
      return '';
    }
    var trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : '';
  }

  function showSuccessToast(message, title) {
    if (!message) {
      return;
    }
    Swal.fire({
      toast: true,
      icon: 'success',
      title: message,
      position: 'top-end',
      showConfirmButton: false,
      timer: 4000,
      timerProgressBar: true
    });
  }

  function showErrorModal(message, title) {
    if (!message) {
      return;
    }
    var html = message.replace(/\n/g, '<br>');
    Swal.fire({
      icon: 'error',
      title: title || 'Error',
      html: html,
      confirmButtonText: 'OK',
      confirmButtonColor: '#d33'
    });
  }

  function handleFlashMessages() {
    var flash = window.__FLASH_MESSAGES__ || {};
    var errorMessage = normalizeMessage(flash.error);
    var successMessage = normalizeMessage(flash.success);
    var errorTitle = normalizeMessage(flash.errorTitle) || 'Error';

    if (errorMessage) {
      showErrorModal(errorMessage, errorTitle);
    }
    if (successMessage) {
      showSuccessToast(successMessage);
    }
  }

  function registerConfirmationHandlers() {
    var forms = document.querySelectorAll('form[data-confirm]');
    forms.forEach(function (form) {
      form.addEventListener('submit', function (event) {
        if (form.dataset.confirmed === 'true') {
          form.dataset.confirmed = '';
          return;
        }
        event.preventDefault();
        var message = normalizeMessage(form.dataset.confirm) || 'Are you sure you want to continue?';
        var title = normalizeMessage(form.dataset.confirmTitle) || 'Are you sure?';
        var confirmText = normalizeMessage(form.dataset.confirmAction) || 'Yes';
        var cancelText = normalizeMessage(form.dataset.cancelAction) || 'Cancel';

        Swal.fire({
          title: title,
          text: message,
          icon: 'warning',
          showCancelButton: true,
          confirmButtonText: confirmText,
          cancelButtonText: cancelText,
          confirmButtonColor: '#d33',
          focusCancel: true
        }).then(function (result) {
          if (result.isConfirmed) {
            form.dataset.confirmed = 'true';
            form.submit();
          }
        });
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    if (typeof Swal === 'undefined') {
      return;
    }
    handleFlashMessages();
    registerConfirmationHandlers();
  });
})();
