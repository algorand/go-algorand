<!DOCTYPE html>
  <head>
    <title>Algorand dispenser</title>
    <script src='https://www.google.com/recaptcha/api.js'>
    </script>
    <script src="https://code.jquery.com/jquery-3.3.1.min.js"
      integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
      crossorigin="anonymous">
    </script>
    <script>
      var ADDRESS_REGEX = /[A-Z0-9]{58}/

      function sanitize(string) {
        const entityMap = {
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;',
          '/': '&#x2F;',
          '`': '&#x60;',
          '=': '&#x3D;'
        };
        return String(string).replace(/[&<>"'`=\/]/g, function (s) {
          return entityMap[s];
        });
      }

      function loadparam() {
        const queryString = window.location.search;
        const urlParams = new URLSearchParams(queryString);
        const account = sanitize(urlParams.get('account'))

        if (ADDRESS_REGEX.test(account)) {
          $('#target').val(account);
        }
      }

      function onload() {
        loadparam();
        $('#dispense').click(function(e) {
          var recaptcha = grecaptcha.getResponse();
          var target = sanitize($('#target').val());

          if (ADDRESS_REGEX.test(target)) {
            $('#status').html('Sending request..');
            var req = $.post('/dispense', {
              recaptcha: recaptcha,
              target: target,
            }, function(data) {
              $('#status').text('Code ' + req.status + ' ' + req.statusText + ': ' + req.responseText);
            }).fail(function() {
              $('#status').text('Code ' + req.status + ' ' + req.statusText + ': ' + req.responseText);
            });
          }
          else {
            $('#status').text('Please enter a valid Algorand address')
          }
        });
      }
    </script>
  </head>
  <body onload="onload()">
    <h1>Algorand dispenser</h1>
    <div class="g-recaptcha" data-sitekey="{{.RecaptchaSiteKey}}">
    </div>
    <div>
      <p>The dispensed Algos have no monetary value and should only be used to test applications.</p>
      <p>This service is gracefully provided to enable development on the Algorand blockchain test networks.</p>
      <p>Please do not abuse it by requesting more Algos than needed.</p>
    </div>
    <div>
      <input id="target" placeholder="target address" size="80">
      <button id="dispense">Dispense</button>
    </div>
    <div>
      Status: <span id="status"></span>
    </div>
  </body>
</html>
