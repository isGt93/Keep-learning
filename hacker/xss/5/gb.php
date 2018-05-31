<!--
gb.php?x=1";alert(1)//
-->

<?php header("Content-Type: Text/html;charset=GBK"); ?>
<head>
<title>gb xss</title>
</head>
<script>
a="<?php echo_$GET['x']; ?>";
</script>