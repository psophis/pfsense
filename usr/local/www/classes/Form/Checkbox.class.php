<?php

class Form_Checkbox extends Form_Input
{
	protected $_description;

	public function __construct($name, $title, $description, $checked, $value = 'yes')
	{
		parent::__construct($name, $title, 'checkbox', $value);

		$this->_description = $description;
		$this->removeClass('form-control');
		$this->addColumnClass('checkbox');

		if ($checked) {
			$this->setAttribute('checked', 'checked');
		}
	}

	public function displayAsRadio()
	{
		return $this->setAttribute('type', 'radio');
	}

	protected function _getInput()
	{
		$input = parent::_getInput();

		if (!isset($this->_description))
			return $input;

		return '<label>'. $input .' '. gettext($this->_description) .'</label>';
	}
}
